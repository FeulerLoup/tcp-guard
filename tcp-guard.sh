#!/usr/bin/env bash
#
# tcp-guard.sh - 入站 TCP 连接采集分析与交互式封禁
#
#   采集一段时间内的入站连接，按来源 IP 汇总（总连接数、新建速率、状态分布），
#   标记可疑来源，并提供交互选项封禁。同时根据物理内存自动校准 conntrack 上限。
#
# 用法:
#   ./tcp-guard.sh              # 默认采集 10 秒
#   ./tcp-guard.sh -d 30        # 采集 30 秒
#   ./tcp-guard.sh -r           # 只看报告，不进入封禁交互
#   ./tcp-guard.sh -n           # 跳过 conntrack 自动调整
#   ./tcp-guard.sh -l           # 列出已封禁 IP 及拦截量，可交互解封
#   ./tcp-guard.sh -u IP        # 解封指定 IP
#

set -uo pipefail

DURATION=10
INTERVAL=0.3
DO_CONNTRACK=1
REPORT_ONLY=0
LIST_BANNED=0
UNBAN_IP=""

# 每个 conntrack 条目约占 320 字节内核内存
CT_ENTRY_BYTES=320
# 每 MB 物理内存分配的条目数，约合 2% 内存占用
CT_PER_MB=64
CT_FLOOR=16384
# conntrack 内存占用不得超过物理内存的 5%
CT_MEM_PERCENT=5

WHITELIST=/etc/tcp-guard-whitelist

C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
C_CYA=$'\033[36m'; C_BLD=$'\033[1m';  C_RST=$'\033[0m'

TMPD=""
cleanup() { [[ -n "$TMPD" && -d "$TMPD" ]] && rm -rf "$TMPD"; }
trap cleanup EXIT INT TERM

die() { echo "${C_RED}错误: $*${C_RST}" >&2; exit 1; }

usage() {
    awk 'NR>1 { if (/^#/) { sub(/^# ?/, ""); print } else exit }' "$0"
    exit 0
}

while getopts "d:rnlu:h" opt; do
    case "$opt" in
        d) DURATION="$OPTARG" ;;
        r) REPORT_ONLY=1 ;;
        n) DO_CONNTRACK=0 ;;
        l) LIST_BANNED=1 ;;
        u) UNBAN_IP="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

[[ $EUID -eq 0 ]] || die "需要 root 权限运行"
command -v ss >/dev/null || die "未找到 ss 命令（apt install iproute2）"
command -v iptables >/dev/null || die "未找到 iptables 命令"

TMPD=$(mktemp -d /tmp/tcpguard.XXXXXX)
RAW="$TMPD/raw"

# ---------------------------------------------------------------- conntrack

calc_conntrack() {
    local total_mb=$1
    local target=$(( total_mb * CT_PER_MB ))
    local p=$CT_FLOOR

    while [[ $(( p * 2 )) -le $target ]]; do p=$(( p * 2 )); done
    # 向上取整更接近目标值时改用高一档的 2 的幂
    if [[ $(( target - p )) -gt $(( p * 2 - target )) ]]; then p=$(( p * 2 )); fi
    [[ $p -lt $CT_FLOOR ]] && p=$CT_FLOOR

    local cap=$(( total_mb * 1048576 * CT_MEM_PERCENT / 100 / CT_ENTRY_BYTES ))
    while [[ $p -gt $cap && $p -gt $CT_FLOOR ]]; do p=$(( p / 2 )); done

    echo "$p"
}

tune_conntrack() {
    if [[ ! -e /proc/sys/net/netfilter/nf_conntrack_max ]]; then
        echo "  conntrack 模块未加载，跳过（封禁规则为无状态匹配，不受影响）"
        return
    fi

    local total_mb cur want hashsize used_mb
    total_mb=$(free -m | awk '/^Mem:/{print $2}')
    cur=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
    want=$(calc_conntrack "$total_mb")
    used_mb=$(( want * CT_ENTRY_BYTES / 1048576 ))

    printf "  物理内存 %s MB  →  建议 nf_conntrack_max = %s (约占用 %s MB 内核内存)\n" \
           "$total_mb" "$want" "$used_mb"

    if [[ $cur -ge $want ]]; then
        echo "  当前值 $cur 已满足要求，无需调整"
        return
    fi

    sysctl -qw net.netfilter.nf_conntrack_max="$want" 2>/dev/null \
        || { echo "  ${C_YEL}调整失败（可能是受限容器环境），跳过${C_RST}"; return; }

    echo "net.netfilter.nf_conntrack_max = $want" > /etc/sysctl.d/99-conntrack.conf

    hashsize=$(( want / 4 ))
    if [[ -w /sys/module/nf_conntrack/parameters/hashsize ]]; then
        echo "$hashsize" > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null
        echo "options nf_conntrack hashsize=$hashsize" > /etc/modprobe.d/nf_conntrack.conf
    fi

    echo "  ${C_GRN}已调整: $cur → $want (hashsize=$hashsize)，并写入 /etc/sysctl.d/99-conntrack.conf${C_RST}"
}

# ---------------------------------------------------------------- 采集

get_listen_ports() {
    ss -tlnH | awk '{
        s=$4; i=length(s)
        while (i>0 && substr(s,i,1)!=":") i--
        p=substr(s,i+1)
        if (p!="" && p!="*") print p
    }' | sort -un | tr '\n' ' '
}

# 保护名单 = 当前活跃 SSH 会话来源 + 白名单文件
# SSH 会话是动态的，断线期间该 IP 会失去保护，故额外支持白名单文件长期固化
get_protected() {
    {
        [[ -n "${SSH_CLIENT:-}" ]] && awk '{print $1}' <<<"$SSH_CLIENT"
        [[ -n "${SSH_CONNECTION:-}" ]] && awk '{print $1}' <<<"$SSH_CONNECTION"
        # 带 state 过滤时 ss 省略 State 列: Recv-Q Send-Q Local Peer
        ss -tanpH state established 2>/dev/null | grep -F 'sshd' | awk '{
            s=$4; i=length(s)
            while (i>0 && substr(s,i,1)!=":") i--
            ip=substr(s,1,i-1)
            gsub(/^\[|\]$/,"",ip); sub(/^::ffff:/,"",ip)
            print ip
        }'
        [[ -r "$WHITELIST" ]] && grep -vE '^\s*(#|$)' "$WHITELIST" | awk '{print $1}'
    } 2>/dev/null | grep -vE '^(127\.|::1$|$)' | sort -u | tr '\n' ' '
}

snapshot() {
    ss -tanH | awk -v id="$1" -v lports=" $2 " '
        function ip_of(s,   i, ip) {
            if (substr(s,1,1)=="[") {
                i = index(s, "]:")
                ip = substr(s, 2, i-2)
            } else {
                i = length(s)
                while (i>0 && substr(s,i,1)!=":") i--
                ip = substr(s, 1, i-1)
            }
            sub(/^::ffff:/, "", ip)
            return ip
        }
        function port_of(s,   i) {
            i = length(s)
            while (i>0 && substr(s,i,1)!=":") i--
            return substr(s, i+1)
        }
        # 不加 state 过滤时 ss 会输出 State 列: State Recv-Q Send-Q Local Peer
        $1 == "LISTEN" { next }
        {
            lp = port_of($4)
            if (index(lports, " " lp " ") == 0) next     # 本地端口非监听端口 => 出站
            pip = ip_of($5)
            if (pip == "" || pip == "*" || pip ~ /^127\./ || pip == "::1") next
            print id "|" pip "|" port_of($5) "|" $1 "|" lp
        }'
}

collect() {
    local lports=$1 id=0 end
    end=$(( $(date +%s) + DURATION ))
    while [[ $(date +%s) -lt $end ]]; do
        snapshot "$id" "$lports" >> "$RAW"
        id=$(( id + 1 ))
        [[ -t 1 ]] && printf "\r  采集中... %ds / %ds   已记录 %s 条" \
               $(( DURATION - (end - $(date +%s)) )) "$DURATION" "$(wc -l < "$RAW")"
        sleep "$INTERVAL"
    done
    [[ -t 1 ]] && printf "\r%-60s\r" " "
    printf "  采集完成，共 %d 次快照，%s 条原始记录\n" "$id" "$(wc -l < "$RAW")"
}

# ---------------------------------------------------------------- 汇总

build_report() {
    local lports=$1 protected=$2
    snapshot "cur" "$lports" > "$TMPD/cur"

    awk -v dur="$DURATION" -v protected=" $protected " -v banned=" $(list_banned) " '
        BEGIN { FS="|" }
        FNR==NR {
            key = $2 "/" $3
            if (!(key in seen)) { seen[key]=1; total[$2]++ }
            ports[$2 "," $5] = 1
            next
        }
        {
            cur[$2]++
            st[$2 "," $4]++
        }
        END {
            for (ip in total) {
                e  = st[ip ",ESTAB"] + 0
                sr = st[ip ",SYN-RECV"] + 0
                # 入站连接中服务端多为被动关闭方，收尾状态集中在 LAST-ACK 而非 TIME-WAIT
                cl = st[ip ",LAST-ACK"] + st[ip ",TIME-WAIT"] + st[ip ",CLOSE-WAIT"] \
                   + st[ip ",FIN-WAIT-1"] + st[ip ",FIN-WAIT-2"] + st[ip ",CLOSING"] + 0
                c  = cur[ip] + 0
                rate = total[ip] / dur

                pl = ""
                for (k in ports) {
                    split(k, a, ",")
                    if (a[1] == ip) pl = (pl == "" ? a[2] : pl "," a[2])
                }

                tag = ""
                if (index(protected, " " ip " ") > 0)   tag = "PROTECTED"
                else if (index(banned, " " ip " ") > 0) tag = "BANNED"
                else if (rate >= 3 || sr >= 3)          tag = "SUSPECT"
                else if (total[ip] >= 50 && e <= 2)     tag = "SUSPECT"

                printf "%s|%d|%.1f|%d|%d|%d|%d|%s|%s\n", ip, total[ip], rate, c, e, sr, cl, pl, tag
            }
        }' "$RAW" "$TMPD/cur" | sort -t'|' -k2,2 -rn > "$TMPD/report"
}

print_report() {
    local n=0 line
    printf "\n${C_BLD}%-4s %-40s %7s %8s %6s %7s %8s %8s %-12s %s${C_RST}\n" \
           "编号" "来源 IP" "总连接" "新建/秒" "当前" "ESTAB" "半连接" "关闭中" "目标端口" "标记"
    printf '%s\n' "$(printf '=%.0s' {1..130})"

    : > "$TMPD/index"
    while IFS='|' read -r ip total rate cur estab sr cl pl tag; do
        n=$(( n + 1 ))
        echo "$n|$ip|$tag" >> "$TMPD/index"

        local mark color
        case "$tag" in
            PROTECTED) mark="[本机SSH·禁封]"; color=$C_CYA ;;
            BANNED)    mark="[已封禁]";       color=$C_GRN ;;
            SUSPECT)   mark="[可疑]";         color=$C_RED ;;
            *)         mark="";               color="" ;;
        esac

        printf "%s%-4s %-40s %7s %8s %6s %7s %8s %8s %-12s %s%s\n" \
               "$color" "$n" "$ip" "$total" "$rate" "$cur" "$estab" "$sr" "$cl" "${pl:--}" "$mark" "$C_RST"
    done < "$TMPD/report"

    [[ $n -eq 0 ]] && echo "  (采集期间没有入站连接)"
    echo
    echo "  ${C_RED}可疑${C_RST}判定依据: 新建速率 >= 3/秒，或半连接 >= 3，或大量连接却极少建立成功"
    echo "  提示: 攻击特征是${C_BLD}高新建速率 + 低 ESTAB${C_RST}；正常用户连接数可能不少，但会稳定停留在 ESTAB"
    echo "  白名单: $WHITELIST ${C_CYA}(每行一个 IP，长期免封)${C_RST}"
}

# ---------------------------------------------------------------- 封禁

list_banned() {
    {
        iptables -S INPUT 2>/dev/null
        ip6tables -S INPUT 2>/dev/null
    } | awk '/-j DROP/ && /-s /{
        for (i=1;i<=NF;i++) if ($i=="-s") { ip=$(i+1); sub(/\/(32|128)$/,"",ip); print ip }
    }' | sort -u | tr '\n' ' '
}

human_bytes() {
    awk -v b="$1" 'BEGIN{
        if      (b >= 1073741824) printf "%.2f GB", b/1073741824
        else if (b >= 1048576)    printf "%.2f MB", b/1048576
        else if (b >= 1024)       printf "%.1f KB", b/1024
        else                      printf "%d B", b
    }'
}

# 从 iptables 计数器读取每条封禁规则的实际拦截量，用于评估封禁效果
show_banned() {
    local n=0 total_pkts=0 total_bytes=0 fam cmd anyaddr
    : > "$TMPD/banindex"

    printf "\n${C_BLD}%-4s %-42s %6s %12s %14s %s${C_RST}\n" \
           "编号" "已封禁 IP" "协议" "拦截包数" "拦截流量" "规则位置"
    printf '%s\n' "$(printf '=%.0s' {1..100})"

    for fam in 4 6; do
        if [[ $fam -eq 4 ]]; then cmd=iptables; anyaddr="0.0.0.0/0"
        else                      cmd=ip6tables; anyaddr="::/0"; fi

        while read -r num pkts bytes src; do
            [[ -z "${num:-}" ]] && continue
            n=$(( n + 1 ))
            echo "$n|$src|$fam" >> "$TMPD/banindex"
            total_pkts=$(( total_pkts + pkts ))
            total_bytes=$(( total_bytes + bytes ))
            printf "%-4s %-42s %6s %12s %14s %s\n" \
                   "$n" "$src" "IPv$fam" "$pkts" "$(human_bytes "$bytes")" "INPUT #$num"
        done < <($cmd -L INPUT -n -v -x --line-numbers 2>/dev/null |
                 awk -v any="$anyaddr" '$4=="DROP" && $9!=any && $9!="" {print $1, $2, $3, $9}')
    done

    if [[ $n -eq 0 ]]; then
        echo "  ${C_CYA}(当前没有封禁任何 IP)${C_RST}"
        echo
        return 1
    fi

    printf '%s\n' "$(printf -- '-%.0s' {1..100})"
    printf "  合计 %d 条规则，累计拦截 %s 个包 / %s\n" \
           "$n" "$total_pkts" "$(human_bytes "$total_bytes")"
    echo "  ${C_CYA}提示: 拦截流量为入站方向。DROP 不回包，真正省下的是被放大的出站流量${C_RST}"
    return 0
}

persist_rules() {
    if command -v netfilter-persistent >/dev/null; then
        netfilter-persistent save >/dev/null 2>&1 \
            && echo "  ${C_GRN}规则已持久化 (netfilter-persistent)${C_RST}" \
            && return
    fi
    mkdir -p /etc/iptables
    iptables-save  > /etc/iptables/rules.v4 2>/dev/null
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null
    echo "  ${C_GRN}规则已保存至 /etc/iptables/rules.v{4,6}${C_RST}"
}

# 按地址形态自动选用 iptables / ip6tables
fw_cmd() { [[ "$1" == *:* ]] && echo ip6tables || echo iptables; }

ban_ip() {
    local ip=$1 cmd
    cmd=$(fw_cmd "$ip")
    if $cmd -C INPUT -s "$ip" -j DROP 2>/dev/null; then
        echo "  $ip 已在封禁列表中，跳过"
        return 1
    fi
    if $cmd -I INPUT -s "$ip" -j DROP 2>/dev/null; then
        echo "  ${C_GRN}已封禁 $ip${C_RST}"
        return 0
    fi
    echo "  ${C_RED}封禁 $ip 失败${C_RST}"
    return 1
}

unban_ip() {
    local ip=$1 cmd
    cmd=$(fw_cmd "$ip")
    if $cmd -D INPUT -s "$ip" -j DROP 2>/dev/null; then
        echo "  ${C_GRN}已解封 $ip${C_RST}"
        return 0
    fi
    echo "  ${C_YEL}$ip 不在封禁列表中${C_RST}"
    return 1
}

interactive_unban() {
    [[ -s "$TMPD/banindex" ]] || return

    echo
    echo "  输入要解封的编号（空格分隔），${C_BLD}回车${C_RST}=跳过:"
    printf "  > "
    read -r input
    [[ -z "${input// }" ]] && { echo "  未做任何改动"; return; }

    local targets=() tok num ip fam found
    for tok in $input; do
        [[ "$tok" =~ ^[0-9]+$ ]] || { echo "  忽略非法输入: $tok"; continue; }
        found=""
        while IFS='|' read -r num ip fam; do
            [[ "$num" == "$tok" ]] && { found=1; targets+=("$ip"); }
        done < "$TMPD/banindex"
        [[ -z "$found" ]] && echo "  编号 $tok 不存在"
    done

    [[ ${#targets[@]} -eq 0 ]] && { echo "  没有可解封的目标"; return; }

    echo
    echo "  即将解封以下 ${#targets[@]} 个 IP:"
    printf "    %s\n" "${targets[@]}"
    printf "  确认执行? [y/N] "
    read -r confirm
    [[ "$confirm" =~ ^[yY]$ ]] || { echo "  已取消"; return; }

    echo
    local ok=0
    for ip in "${targets[@]}"; do
        unban_ip "$ip" && ok=$(( ok + 1 ))
    done
    [[ $ok -gt 0 ]] && persist_rules
}

interactive_ban() {
    [[ -s "$TMPD/index" ]] || return

    echo
    echo "  输入要封禁的编号（空格分隔），${C_BLD}a${C_RST}=全部可疑项，${C_BLD}回车${C_RST}=跳过:"
    printf "  > "
    read -r input
    [[ -z "${input// }" ]] && { echo "  未做任何改动"; return; }

    local targets=()
    if [[ "$input" == "a" || "$input" == "A" ]]; then
        while IFS='|' read -r n ip tag; do
            [[ "$tag" == "SUSPECT" ]] && targets+=("$ip")
        done < "$TMPD/index"
    else
        for tok in $input; do
            [[ "$tok" =~ ^[0-9]+$ ]] || { echo "  忽略非法输入: $tok"; continue; }
            local found=""
            while IFS='|' read -r n ip tag; do
                if [[ "$n" == "$tok" ]]; then
                    found=1
                    if [[ "$tag" == "PROTECTED" ]]; then
                        echo "  ${C_RED}拒绝: $ip 是当前 SSH 来源，封禁会导致你断开连接${C_RST}"
                    elif [[ "$tag" == "BANNED" ]]; then
                        echo "  $ip 已处于封禁状态"
                    else
                        targets+=("$ip")
                    fi
                fi
            done < "$TMPD/index"
            [[ -z "$found" ]] && echo "  编号 $tok 不存在"
        done
    fi

    [[ ${#targets[@]} -eq 0 ]] && { echo "  没有可封禁的目标"; return; }

    echo
    echo "  即将封禁以下 ${#targets[@]} 个 IP:"
    printf "    %s\n" "${targets[@]}"
    printf "  确认执行? [y/N] "
    read -r confirm
    [[ "$confirm" =~ ^[yY]$ ]] || { echo "  已取消"; return; }

    echo
    local ok=0
    for ip in "${targets[@]}"; do
        ban_ip "$ip" && ok=$(( ok + 1 ))
    done

    [[ $ok -gt 0 ]] && persist_rules
    echo
    echo "  解封命令: $0 -u <IP>"
}

# ---------------------------------------------------------------- 主流程

if [[ -n "$UNBAN_IP" ]]; then
    unban_ip "$UNBAN_IP" && persist_rules
    exit 0
fi

if [[ $LIST_BANNED -eq 1 ]]; then
    show_banned && { [[ $REPORT_ONLY -eq 1 ]] || interactive_unban; }
    echo
    exit 0
fi

echo
echo "${C_BLD}[1/3] conntrack 容量校准${C_RST}"
if [[ $DO_CONNTRACK -eq 1 ]]; then
    tune_conntrack
else
    echo "  已跳过 (-n)"
fi

echo
echo "${C_BLD}[2/3] 采集入站连接 (${DURATION}s)${C_RST}"
LISTEN_PORTS=$(get_listen_ports)
PROTECTED=$(get_protected)
echo "  监听端口: ${LISTEN_PORTS:-无}"
echo "  保护名单: ${PROTECTED:-无} ${C_CYA}(当前 SSH 来源，不可封禁)${C_RST}"
collect "$LISTEN_PORTS"

echo
echo "${C_BLD}[3/3] 汇总${C_RST}"
build_report "$LISTEN_PORTS" "$PROTECTED"
print_report

[[ $REPORT_ONLY -eq 1 ]] || interactive_ban
echo
