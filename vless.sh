#!/bin/bash
#═══════════════════════════════════════════════════════════════════════════════
#  多协议代理一键部署脚本 v2.0 (全系统通用版)
#  支持协议: VLESS+Reality / VLESS+Reality+XHTTP / VLESS+WS / VLESS-XTLS-Vision / SOCKS5 / SS2022 / HY2 / Trojan / Snell v4 / Snell v5 / AnyTLS / TUIC
#  适配: Alpine/Debian/Ubuntu/CentOS
#  核心特性: 多协议共存 / BBR优化 / Watchdog 守护 / FwMark 内核级防死锁
#  
#  作者: Chil30
#  项目地址: https://github.com/Chil30/vless-all-in-one
#═══════════════════════════════════════════════════════════════════════════════

readonly VERSION="2.0"
readonly AUTHOR="Chil30"
readonly REPO_URL="https://github.com/Chil30/vless-all-in-one"
readonly CFG="/etc/vless-reality"
readonly SOCKS_PORT="10808"
readonly REDIR_PORT="10809"
readonly TUN_IP="10.0.85.1"
readonly TUN_GW="10.0.85.2"
readonly FWMARK="255"

# 颜色
R='\e[31m'; G='\e[32m'; Y='\e[33m'; C='\e[36m'; W='\e[97m'; D='\e[2m'; NC='\e[0m'
set -o pipefail

# 系统检测
if [[ -f /etc/alpine-release ]]; then
    DISTRO="alpine"
elif [[ -f /etc/redhat-release ]]; then
    DISTRO="centos"
else
    DISTRO="debian"
fi

#═══════════════════════════════════════════════════════════════════════════════
# 多协议管理系统
#═══════════════════════════════════════════════════════════════════════════════

# 协议分类定义
XRAY_PROTOCOLS="vless vless-xhttp vless-ws vless-vision trojan socks ss2022"
INDEPENDENT_PROTOCOLS="hy2 tuic snell snell-v5 anytls"

# 协议注册和状态管理
register_protocol() {
    local protocol=$1
    mkdir -p "$CFG"
    echo "$protocol" >> "$CFG/installed_protocols"
    sort -u "$CFG/installed_protocols" -o "$CFG/installed_protocols" 2>/dev/null
}

unregister_protocol() {
    local protocol=$1
    [[ -f "$CFG/installed_protocols" ]] && sed -i "/^$protocol$/d" "$CFG/installed_protocols"
}

get_installed_protocols() {
    [[ -f "$CFG/installed_protocols" ]] && cat "$CFG/installed_protocols" || echo ""
}

is_protocol_installed() {
    local protocol=$1
    [[ -f "$CFG/installed_protocols" ]] && grep -q "^$protocol$" "$CFG/installed_protocols"
}

get_xray_protocols() {
    local installed=$(get_installed_protocols)
    for protocol in $XRAY_PROTOCOLS; do
        if echo "$installed" | grep -q "^$protocol$"; then
            echo "$protocol"
        fi
    done
}

get_independent_protocols() {
    local installed=$(get_installed_protocols)
    for protocol in $INDEPENDENT_PROTOCOLS; do
        if echo "$installed" | grep -q "^$protocol$"; then
            echo "$protocol"
        fi
    done
}

# 生成 Xray 多 inbounds 配置
generate_xray_config() {
    local xray_protocols=$(get_xray_protocols)
    [[ -z "$xray_protocols" ]] && return 1
    
    mkdir -p "$CFG"
    cat > "$CFG/config.json" << 'EOF'
{
    "log": {"loglevel": "warning"},
    "inbounds": [],
    "outbounds": [{"protocol": "freedom"}]
}
EOF
    
    # 为每个 Xray 协议添加 inbound
    for protocol in $xray_protocols; do
        add_xray_inbound "$protocol"
    done
}

# 添加 Xray inbound 配置
add_xray_inbound() {
    local protocol=$1
    local info_file="$CFG/${protocol}.info"
    [[ ! -f "$info_file" ]] && return 1
    
    source "$info_file"
    local inbound_json
    
    case "$protocol" in
        vless)
            inbound_json=$(cat << EOF
{
    "port": $port, "listen": "::", "protocol": "vless",
    "settings": {"clients": [{"id": "$uuid", "flow": "xtls-rprx-vision"}], "decryption": "none"},
    "streamSettings": {
        "network": "tcp", "security": "reality",
        "realitySettings": {"show": false, "dest": "$sni:443", "xver": 0, "serverNames": ["$sni"], "privateKey": "$private_key", "shortIds": ["$short_id"]}
    },
    "tag": "vless-reality"
}
EOF
)
            ;;
        vless-xhttp)
            inbound_json=$(cat << EOF
{
    "port": $port, "listen": "::", "protocol": "vless",
    "settings": {"clients": [{"id": "$uuid"}], "decryption": "none"},
    "streamSettings": {
        "network": "xhttp",
        "xhttpSettings": {"path": "$path", "mode": "auto"},
        "security": "reality",
        "realitySettings": {"show": false, "dest": "$sni:443", "xver": 0, "serverNames": ["$sni"], "privateKey": "$private_key", "shortIds": ["$short_id"]}
    },
    "tag": "vless-xhttp"
}
EOF
)
            ;;
        trojan)
            inbound_json=$(cat << EOF
{
    "port": $port, "listen": "::", "protocol": "trojan",
    "settings": {
        "clients": [{"password": "$password"}],
        "fallbacks": [{"dest": 80}]
    },
    "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
            "certificates": [{
                "certificateFile": "$CFG/certs/server.crt",
                "keyFile": "$CFG/certs/server.key"
            }]
        }
    },
    "tag": "trojan"
}
EOF
)
            ;;
        socks)
            inbound_json=$(cat << EOF
{
    "port": $port,
    "listen": "::",
    "protocol": "socks",
    "settings": {
        "auth": "password",
        "accounts": [{"user": "$username", "pass": "$password"}],
        "udp": true,
        "ip": "::"
    },
    "tag": "socks5"
}
EOF
)
            ;;
        vless-ws)
            inbound_json=$(cat << EOF
{
    "port": $port, "listen": "::", "protocol": "vless",
    "settings": {"clients": [{"id": "$uuid"}], "decryption": "none"},
    "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
            "certificates": [{
                "certificateFile": "$CFG/certs/server.crt",
                "keyFile": "$CFG/certs/server.key"
            }]
        },
        "wsSettings": {"path": "$path", "headers": {"Host": "$sni"}}
    },
    "tag": "vless-ws"
}
EOF
)
            ;;
        vless-vision)
            inbound_json=$(cat << EOF
{
    "port": $port, "listen": "::", "protocol": "vless",
    "settings": {"clients": [{"id": "$uuid", "flow": "xtls-rprx-vision"}], "decryption": "none"},
    "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
            "rejectUnknownSni": false,
            "minVersion": "1.2",
            "alpn": ["h2", "http/1.1"],
            "certificates": [{
                "certificateFile": "$CFG/certs/server.crt",
                "keyFile": "$CFG/certs/server.key"
            }]
        }
    },
    "tag": "vless-vision"
}
EOF
)
            ;;
        ss2022)
            inbound_json=$(cat << EOF
{
    "port": $port, "listen": "::", "protocol": "shadowsocks",
    "settings": {
        "method": "$method",
        "password": "$password",
        "network": "tcp,udp"
    },
    "tag": "ss2022"
}
EOF
)
            ;;
    esac
    
    # 使用 jq 添加 inbound 到配置文件
    if [[ -n "$inbound_json" ]]; then
        local temp_config=$(mktemp)
        echo "$inbound_json" | jq -c '.' > /tmp/inbound.json
        jq '.inbounds += [input]' "$CFG/config.json" /tmp/inbound.json > "$temp_config"
        mv "$temp_config" "$CFG/config.json"
        rm -f /tmp/inbound.json
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 基础工具函数
#═══════════════════════════════════════════════════════════════════════════════
_line()  { echo -e "${D}─────────────────────────────────────────────${NC}"; }
_dline() { echo -e "${C}═════════════════════════════════════════════${NC}"; }
_info()  { echo -e "  ${C}▸${NC} $1"; }
_ok()    { echo -e "  ${G}✓${NC} $1"; }
_err()   { echo -e "  ${R}✗${NC} $1"; }
_warn()  { echo -e "  ${Y}!${NC} $1"; }
_item()  { echo -e "  ${G}$1${NC}) $2"; }
_pause() { echo ""; read -rp "  按回车继续..."; }

_header() {
    clear; echo ""
    _dline
    echo -e "      ${W}多协议代理${NC} ${D}一键部署${NC} ${C}v${VERSION}${NC}"
    echo -e "      ${D}作者: ${AUTHOR}  快捷命令: vless${NC}"
    echo -e "      ${D}${REPO_URL}${NC}"
    _dline
}

get_protocol() { [[ -f "$CFG/protocol" ]] && cat "$CFG/protocol" || echo "vless"; }

get_protocol_name() {
    case "$1" in
        vless) echo "VLESS+Reality" ;;
        vless-xhttp) echo "VLESS+Reality+XHTTP" ;;
        vless-vision) echo "VLESS-XTLS-Vision" ;;
        vless-ws) echo "VLESS+WS+TLS" ;;
        ss2022) echo "Shadowsocks 2022" ;;
        hy2) echo "Hysteria2" ;;
        trojan) echo "Trojan" ;;
        snell) echo "Snell v4" ;;
        snell-v5) echo "Snell v5" ;;
        tuic) echo "TUIC v5" ;;
        anytls) echo "AnyTLS" ;;
        socks) echo "SOCKS5" ;;
        *) echo "未知" ;;
    esac
}

check_root()      { [[ $EUID -ne 0 ]] && { _err "请使用 root 权限运行"; exit 1; }; }
check_cmd()       { command -v "$1" &>/dev/null; }
check_installed() { [[ -d "$CFG" && ( -f "$CFG/config.json" || -f "$CFG/config.yaml" || -f "$CFG/config.conf" || -f "$CFG/info" ) ]]; }
get_role()        { [[ -f "$CFG/role" ]] && cat "$CFG/role" || echo ""; }
get_mode()        { [[ -f "$CFG/mode" ]] && cat "$CFG/mode" || echo "tun"; }
is_paused()       { [[ -f "$CFG/paused" ]]; }

get_mode_name() {
    case "$1" in
        tun) echo "TUN网卡" ;;
        global) echo "全局代理" ;;
        socks) echo "SOCKS5代理" ;;
        *) echo "未知" ;;
    esac
}

#═══════════════════════════════════════════════════════════════════════════════
# 核心功能：强力清理 & 时间同步
#═══════════════════════════════════════════════════════════════════════════════
force_cleanup() {
    svc stop vless-watchdog 2>/dev/null
    svc stop vless-tun 2>/dev/null
    svc stop vless-global 2>/dev/null
    svc stop vless-reality 2>/dev/null
    killall tun2socks xray hysteria snell-server tuic-server 2>/dev/null
    ip link del tun0 2>/dev/null
    while ip rule show | grep -q "lookup 55"; do ip rule del lookup 55 2>/dev/null; done
    ip route flush table 55 2>/dev/null
    rm -f /tmp/vless-tun-info /tmp/vless-tun-routes
    iptables -t nat -D OUTPUT -p tcp -j VLESS_PROXY 2>/dev/null
    iptables -t nat -F VLESS_PROXY 2>/dev/null
    iptables -t nat -X VLESS_PROXY 2>/dev/null
    ip6tables -t nat -D OUTPUT -p tcp -j VLESS_PROXY 2>/dev/null
    ip6tables -t nat -F VLESS_PROXY 2>/dev/null
    ip6tables -t nat -X VLESS_PROXY 2>/dev/null
}

sync_time() {
    _info "同步系统时间..."
    local http_time=$(curl -sI --connect-timeout 3 http://www.baidu.com | grep Date | cut -d' ' -f2-)
    if [[ -n "$http_time" ]]; then
        date -s "$http_time" &>/dev/null
        _ok "时间同步完成 (HTTP)"
        return
    fi
    if command -v chronyd &>/dev/null; then
        timeout 3 chronyd -q 'server pool.ntp.org iburst' &>/dev/null && { _ok "时间同步完成 (NTP)"; return; }
    fi
    if command -v ntpdate &>/dev/null; then
        timeout 3 ntpdate pool.ntp.org &>/dev/null && { _ok "时间同步完成 (NTP)"; return; }
    fi
    _warn "时间同步失败 (跳过)"
}

#═══════════════════════════════════════════════════════════════════════════════
# 多协议管理函数
#═══════════════════════════════════════════════════════════════════════════════

# 列出已安装的协议 (兼容函数，实际使用 get_installed_protocols)
list_installed_protocols() {
    get_installed_protocols
}

# 查看已安装协议配置 (已整合到 show_all_protocols_info)
# list_and_show_configs() - 已删除，使用 show_all_protocols_info 替代

# 显示特定协议配置 (已整合到 show_single_protocol_info)
# show_protocol_config() - 已删除，使用 show_single_protocol_info 替代

# 管理服务菜单 (已整合到 manage_protocol_services)
# manage_services() - 已删除，使用 manage_protocol_services 替代

# 以下服务管理函数已整合到 start_services/stop_services
# start_all_protocol_services() - 已删除
# stop_all_protocol_services() - 已删除  
# restart_all_protocol_services() - 已删除

# 卸载特定协议 (使用 get_installed_protocols)
uninstall_specific() {
    local installed=$(get_installed_protocols)
    [[ -z "$installed" ]] && { _warn "未安装任何协议"; return; }
    
    local protocols=($installed)
    
    _header
    echo -e "  ${W}卸载协议${NC}"
    _line
    
    local i=1
    for protocol in "${protocols[@]}"; do
        echo -e "  ${G}$i${NC}) $(get_protocol_name $protocol)"
        ((i++))
    done
    
    echo ""
    read -rp "  选择要卸载的协议 [1-${#protocols[@]}]: " choice
    
    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le ${#protocols[@]} ]]; then
        local selected_protocol="${protocols[$((choice-1))]}"
        
        echo -e "  ${R}警告: 即将卸载 $(get_protocol_name $selected_protocol)${NC}"
        read -rp "  确认卸载? [y/N]: " confirm
        
        if [[ "$confirm" =~ ^[yY]$ ]]; then
            uninstall_protocol "$selected_protocol"
        fi
    fi
}

# 卸载指定协议
uninstall_protocol() {
    local protocol="$1"
    local service_name="vless-reality-${protocol}"
    
    _info "停止服务..."
    svc stop "$service_name"
    
    _info "删除服务文件..."
    if [[ "$DISTRO" == "alpine" ]]; then
        rc-update del "$service_name" default 2>/dev/null
        rm -f "/etc/init.d/${service_name}"
    else
        systemctl disable "$service_name" 2>/dev/null
        rm -f "/etc/systemd/system/${service_name}.service"
        systemctl daemon-reload
    fi
    
    _info "删除配置文件..."
    rm -f "$CFG/${protocol}.info"
    rm -f "$CFG/${protocol}.json"
    rm -f "$CFG/${protocol}.yaml"
    rm -f "$CFG/${protocol}.conf"
    
    _ok "协议 $(get_protocol_name $protocol) 卸载完成"
}

#═══════════════════════════════════════════════════════════════════════════════
# 网络工具
#═══════════════════════════════════════════════════════════════════════════════
get_ipv4() { curl -4 -sf --connect-timeout 5 ip.sb 2>/dev/null || curl -4 -sf --connect-timeout 5 ifconfig.me 2>/dev/null; }
get_ipv6() { curl -6 -sf --connect-timeout 5 ip.sb 2>/dev/null || curl -6 -sf --connect-timeout 5 ifconfig.me 2>/dev/null; }

gen_uuid()  { cat /proc/sys/kernel/random/uuid 2>/dev/null || printf '%04x%04x-%04x-%04x-%04x-%04x%04x%04x\n' $RANDOM $RANDOM $RANDOM $(($RANDOM&0x0fff|0x4000)) $(($RANDOM&0x3fff|0x8000)) $RANDOM $RANDOM $RANDOM; }

# 优化后的端口生成函数 - 增加端口冲突检测
gen_port() {
    local port
    while true; do
        port=$(shuf -i 10000-60000 -n 1 2>/dev/null || echo $((RANDOM % 50000 + 10000)))
        # 检查端口是否被占用 (TCP 和 UDP)
        if ! ss -tuln 2>/dev/null | grep -q ":$port " && ! netstat -tuln 2>/dev/null | grep -q ":$port "; then
            echo "$port"
            return
        fi
    done
}

gen_sid()   { head -c 4 /dev/urandom 2>/dev/null | xxd -p || printf '%08x' $RANDOM; }

# 新增通用配置保存函数
save_config() {
    local proto=$1
    local content=$2
    local ext=$3 # json 或 yaml 或 conf
    mkdir -p "$CFG"
    cat > "$CFG/${proto}.${ext}" << EOF
$content
EOF
}

save_info() {
    local proto=$1
    local content=$2
    mkdir -p "$CFG"
    cat > "$CFG/${proto}.info" << EOF
$content
EOF
}
gen_sni()   { local s=("www.microsoft.com" "www.apple.com" "www.amazon.com" "www.cloudflare.com" "www.mozilla.org" "www.github.com"); echo "${s[$((RANDOM % ${#s[@]}))]}"; }
gen_password() { head -c 16 /dev/urandom 2>/dev/null | base64 | tr -d '/+=' | head -c 16 || printf '%s%s' $RANDOM $RANDOM | md5sum | head -c 16; }

urlencode() {
    local s="$1" i c o=""
    for ((i=0; i<${#s}; i++)); do
        c="${s:i:1}"
        case "$c" in
            [-_.~a-zA-Z0-9]) o+="$c" ;;
            *) printf -v c '%%%02x' "'$c"; o+="$c" ;;
        esac
    done
    echo "$o"
}

gen_vless_link() {
    local ip="$1" port="$2" uuid="$3" pbk="$4" sid="$5" sni="$6"
    printf '%s\n' "vless://${uuid}@${ip}:${port}?encryption=none&security=reality&type=tcp&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}&flow=xtls-rprx-vision#${uuid:0:8}-reality"
}

gen_vless_xhttp_link() {
    local ip="$1" port="$2" uuid="$3" pbk="$4" sid="$5" sni="$6" path="${7:-/}"
    printf '%s\n' "vless://${uuid}@${ip}:${port}?encryption=none&security=reality&type=xhttp&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}&path=$(urlencode "$path")&mode=auto#${uuid:0:8}-reality-xhttp"
}

gen_qr() { printf '%s\n' "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=$(urlencode "$1")"; }

# 生成各协议分享链接
gen_hy2_link() {
    local ip="$1" port="$2" password="$3" sni="$4"
    printf '%s\n' "hysteria2://${password}@${ip}:${port}?sni=${sni}&insecure=1#HY2-${ip}"
}

gen_trojan_link() {
    local ip="$1" port="$2" password="$3" sni="$4"
    printf '%s\n' "trojan://${password}@${ip}:${port}?security=tls&sni=${sni}&type=tcp&allowInsecure=1#Trojan-${ip}"
}

gen_vless_ws_link() {
    local ip="$1" port="$2" uuid="$3" sni="$4" path="${5:-/}"
    printf '%s\n' "vless://${uuid}@${ip}:${port}?encryption=none&security=tls&sni=${sni}&type=ws&host=${sni}&path=$(urlencode "$path")&allowInsecure=1#VLESS-WS-${ip}"
}

gen_vless_vision_link() {
    local ip="$1" port="$2" uuid="$3" sni="$4"
    printf '%s\n' "vless://${uuid}@${ip}:${port}?encryption=none&security=tls&sni=${sni}&type=tcp&flow=xtls-rprx-vision&allowInsecure=1#VLESS-Vision-${ip}"
}

gen_ss2022_link() {
    local ip="$1" port="$2" method="$3" password="$4"
    local userinfo=$(printf '%s:%s' "$method" "$password" | base64 -w 0 2>/dev/null || printf '%s:%s' "$method" "$password" | base64)
    printf '%s\n' "ss://${userinfo}@${ip}:${port}#SS2022-${ip}"
}

gen_snell_link() {
    local ip="$1" port="$2" psk="$3" version="${4:-4}"
    # Snell 没有标准URI格式，使用自定义格式
    printf '%s\n' "snell://${psk}@${ip}:${port}?version=${version}#Snell-${ip}"
}

gen_tuic_link() {
    local ip="$1" port="$2" uuid="$3" password="$4" sni="$5"
    printf '%s\n' "tuic://${uuid}:${password}@${ip}:${port}?congestion_control=bbr&alpn=h3&sni=${sni}&udp_relay_mode=native&allow_insecure=1#TUIC-${ip}"
}

gen_anytls_link() {
    local ip="$1" port="$2" password="$3" sni="$4"
    printf '%s\n' "anytls://${password}@${ip}:${port}?sni=${sni}&allowInsecure=1#AnyTLS-${ip}"
}

gen_snell_v5_link() {
    local ip="$1" port="$2" psk="$3" version="${4:-5}"
    # Snell v5 使用自定义格式
    printf '%s\n' "snell://${psk}@${ip}:${port}?version=${version}#Snell-v5-${ip}"
}

gen_socks_link() {
    local ip="$1" port="$2" username="$3" password="$4"
    if [[ -n "$username" && -n "$password" ]]; then
        # Telegram 格式的 SOCKS5 代理链接
        printf '%s\n' "https://t.me/socks?server=${ip}&port=${port}&user=${username}&pass=${password}"
    else
        printf '%s\n' "socks5://${ip}:${port}#SOCKS5-${ip}"
    fi
}

test_connection() {
    local role=$(get_role)
    if [[ "$role" == "server" ]]; then
        # 检查所有已安装协议的端口
        local installed=$(get_installed_protocols)
        for proto in $installed; do
            if [[ -f "$CFG/${proto}.info" ]]; then
                source "$CFG/${proto}.info"
                if ss -tlnp 2>/dev/null | grep -q ":$port " || ss -ulnp 2>/dev/null | grep -q ":$port "; then
                    _ok "$(get_protocol_name $proto) 端口 $port 已监听"
                else
                    _err "$(get_protocol_name $proto) 端口 $port 未监听"
                fi
            fi
        done
    else
        _info "验证代理效果..."
        
        # 先检查本地 SOCKS5 代理是否可用
        if ! ss -tlnp 2>/dev/null | grep -q ":$SOCKS_PORT "; then
            _err "本地 SOCKS5 代理未监听 (端口 $SOCKS_PORT)"
            return 1
        fi
        
        local start=$(date +%s%3N 2>/dev/null || echo $(($(date +%s)*1000)))
        local result=$(curl -x socks5h://127.0.0.1:$SOCKS_PORT -sf -m 10 ip.sb 2>/dev/null)
        local end=$(date +%s%3N 2>/dev/null || echo $(($(date +%s)*1000)))
        local latency=$((end - start))
        if [[ -n "$result" ]]; then
             local location=$(curl -x socks5h://127.0.0.1:$SOCKS_PORT -sf -m 5 "http://ip-api.com/line/$result?fields=country" 2>/dev/null)
             _ok "代理已生效!"
             echo -e "  出口IP: ${G}$result${NC} ${D}($location)${NC}  延迟: ${G}${latency}ms${NC}"
        else
             _err "代理连接超时，请检查服务端状态"
             # 显示调试信息
             echo -e "  ${D}调试: 检查客户端日志 journalctl -u vless-* -n 20${NC}"
        fi
    fi
}

test_latency() {
    local ip="$1" port="$2" proto="${3:-tcp}" start end
    start=$(date +%s%3N 2>/dev/null || echo $(($(date +%s)*1000)))
    
    # UDP协议无法用TCP测试
    if [[ "$proto" == "hy2" || "$proto" == "tuic" ]]; then
        # 用ping测试基本延迟
        if ping -c 1 -W 2 "$ip" &>/dev/null; then
            end=$(date +%s%3N 2>/dev/null || echo $(($(date +%s)*1000)))
            echo "$((end-start))ms"
        else
            echo "UDP"
        fi
    else
        if timeout 3 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
            end=$(date +%s%3N 2>/dev/null || echo $(($(date +%s)*1000)))
            echo "$((end-start))ms"
        else
            echo "超时"
        fi
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 安装依赖 (v3.3 适配 CentOS)
#═══════════════════════════════════════════════════════════════════════════════
install_deps() {
    _info "检查系统依赖..."
    if [[ "$DISTRO" == "alpine" ]]; then
        _info "更新软件包索引..."
        if ! apk update &>/dev/null; then
            _err "更新软件包索引失败"
            return 1
        fi
        
        local deps="curl jq unzip iproute2 iptables ip6tables gcompat openssl"
        _info "安装依赖: $deps"
        if ! apk add --no-cache $deps 2>/tmp/apk_error.log; then
            _err "依赖安装失败，详细错误："
            cat /tmp/apk_error.log
            rm -f /tmp/apk_error.log
            return 1
        fi
    elif [[ "$DISTRO" == "centos" ]]; then
        _info "安装 EPEL 源..."
        if ! yum install -y epel-release &>/dev/null; then
            _err "EPEL 源安装失败"
            return 1
        fi
        
        local deps="curl jq unzip iproute iptables vim-common openssl"
        _info "安装依赖: $deps"
        if ! yum install -y $deps 2>/tmp/yum_error.log; then
            _err "依赖安装失败，详细错误："
            cat /tmp/yum_error.log
            rm -f /tmp/yum_error.log
            return 1
        fi
    else
        _info "更新软件包索引..."
        if ! apt-get update -qq 2>/tmp/apt_update_error.log; then
            _err "更新软件包索引失败，详细错误："
            cat /tmp/apt_update_error.log
            rm -f /tmp/apt_update_error.log
            return 1
        fi
        
        local deps="curl jq unzip iproute2 xxd openssl"
        _info "安装依赖: $deps"
        if ! apt-get install -y -qq $deps 2>/tmp/apt_error.log; then
            _err "依赖安装失败，详细错误："
            cat /tmp/apt_error.log
            rm -f /tmp/apt_error.log
            return 1
        fi
    fi
}

# 安装 tun2socks (TUN模式必需)
install_tun2socks() {
    [[ -x "/usr/local/bin/tun2socks" ]] && { _ok "tun2socks 已安装"; return 0; }
    
    local arch=$(uname -m) t2s_arch
    case $arch in
        x86_64)  t2s_arch="amd64" ;;
        aarch64) t2s_arch="arm64" ;;
        armv7l)  t2s_arch="armv7" ;;
        *) _warn "不支持的架构，跳过tun2socks安装"; return 1 ;;
    esac
    
    _info "安装 tun2socks..."
    local tmp=$(mktemp -d)
    if curl -sLo "$tmp/t2s.zip" --connect-timeout 60 "https://github.com/xjasonlyu/tun2socks/releases/latest/download/tun2socks-linux-${t2s_arch}.zip"; then
        unzip -oq "$tmp/t2s.zip" -d "$tmp/" 2>/dev/null
        local bin=$(find "$tmp" -name "tun2socks*" -type f | head -1)
        if [[ -n "$bin" ]]; then
            mv "$bin" /usr/local/bin/tun2socks
            chmod +x /usr/local/bin/tun2socks
            rm -rf "$tmp"
            _ok "tun2socks 已安装"
            return 0
        else
            rm -rf "$tmp"
            _err "tun2socks 安装失败"
            return 1
        fi
    else
        rm -rf "$tmp"
        _err "tun2socks 下载失败"
        return 1
    fi
}

install_xray() {
    check_cmd xray && { _ok "Xray 已安装"; return 0; }
    
    local arch=$(uname -m) xarch
    case $arch in
        x86_64)  xarch="64" ;;
        aarch64) xarch="arm64-v8a" ;;
        armv7l)  xarch="arm32-v7a" ;;
        *) _err "不支持的架构: $arch"; return 1 ;;
    esac

    _info "安装 Xray..."
    local tmp=$(mktemp -d)
    if curl -sLo "$tmp/xray.zip" --connect-timeout 30 "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${xarch}.zip"; then
        unzip -oq "$tmp/xray.zip" -d "$tmp/" || { rm -rf "$tmp"; _err "解压失败"; return 1; }
        install -m 755 "$tmp/xray" /usr/local/bin/xray
        mkdir -p /usr/local/share/xray
        [[ -f "$tmp/geoip.dat" ]] && install -m 644 "$tmp/geoip.dat" /usr/local/share/xray/
        [[ -f "$tmp/geosite.dat" ]] && install -m 644 "$tmp/geosite.dat" /usr/local/share/xray/
        rm -rf "$tmp"
        _ok "Xray 已安装"
    else
        rm -rf "$tmp"; _err "下载 Xray 失败"; return 1
    fi
}

# 安装 Hysteria2
install_hysteria() {
    check_cmd hysteria && { _ok "Hysteria2 已安装"; return 0; }
    
    local arch=$(uname -m) harch
    case $arch in
        x86_64)  harch="amd64" ;;
        aarch64) harch="arm64" ;;
        armv7l)  harch="armv7" ;;
        *) _err "不支持的架构: $arch"; return 1 ;;
    esac

    _info "安装 Hysteria2..."
    if curl -sLo /usr/local/bin/hysteria --connect-timeout 60 "https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${harch}"; then
        chmod +x /usr/local/bin/hysteria
        _ok "Hysteria2 已安装"
    else
        _err "下载 Hysteria2 失败"; return 1
    fi
}

# 安装 Snell
install_snell() {
    check_cmd snell-server && { _ok "Snell 已安装"; return 0; }
    
    local arch=$(uname -m) sarch
    case $arch in
        x86_64)  sarch="amd64" ;;
        aarch64) sarch="aarch64" ;;
        armv7l)  sarch="armv7l" ;;
        *) _err "不支持的架构: $arch"; return 1 ;;
    esac

    _info "安装 Snell v4..."
    local tmp=$(mktemp -d)
    if curl -sLo "$tmp/snell.zip" --connect-timeout 60 "https://dl.nssurge.com/snell/snell-server-v4.1.1-linux-${sarch}.zip"; then
        unzip -oq "$tmp/snell.zip" -d "$tmp/" 2>/dev/null
        install -m 755 "$tmp/snell-server" /usr/local/bin/snell-server
        rm -rf "$tmp"
        _ok "Snell 已安装"
    else
        rm -rf "$tmp"; _err "下载 Snell 失败"; return 1
    fi
}

# 安装 Snell v5
install_snell_v5() {
    check_cmd snell-server-v5 && { _ok "Snell v5 已安装"; return 0; }
    
    local arch=$(uname -m) sarch
    case $arch in
        x86_64)  sarch="amd64" ;;
        aarch64) sarch="aarch64" ;;
        armv7l)  sarch="armv7l" ;;
        *) _err "不支持的架构: $arch"; return 1 ;;
    esac

    _info "安装 Snell v5..."
    local tmp=$(mktemp -d)
    
    # 获取最新版本号
    local latest_version
    latest_version=$(curl -s "https://api.github.com/repos/surge-networks/snell/releases/latest" | grep '"tag_name"' | cut -d'"' -f4 | sed 's/^v//')
    if [[ -z "$latest_version" ]]; then
        latest_version="5.0.1"  # fallback 版本
        _warn "无法获取最新版本，使用默认版本 $latest_version"
    else
        _info "检测到最新版本: v$latest_version"
    fi
    
    if curl -sLo "$tmp/snell-v5.zip" --connect-timeout 60 "https://dl.nssurge.com/snell/snell-server-v${latest_version}-linux-${sarch}.zip"; then
        unzip -oq "$tmp/snell-v5.zip" -d "$tmp/" 2>/dev/null
        install -m 755 "$tmp/snell-server" /usr/local/bin/snell-server-v5
        rm -rf "$tmp"
        _ok "Snell v5 已安装"
    else
        rm -rf "$tmp"; _err "下载 Snell v5 失败"; return 1
    fi
}

# 安装 AnyTLS
install_anytls() {
    check_cmd anytls-server && { _ok "AnyTLS 已安装"; return 0; }
    
    local arch=$(uname -m) aarch
    case $arch in
        x86_64)  aarch="amd64" ;;
        aarch64) aarch="arm64" ;;
        armv7l)  aarch="armv7" ;;
        *) _err "不支持的架构: $arch"; return 1 ;;
    esac

    _info "安装 AnyTLS..."
    local tmp=$(mktemp -d)
    local version="v0.0.11"  # 使用最新版本
    if curl -sLo "$tmp/anytls.zip" --connect-timeout 60 "https://github.com/anytls/anytls-go/releases/download/${version}/anytls_${version#v}_linux_${aarch}.zip"; then
        unzip -oq "$tmp/anytls.zip" -d "$tmp/" 2>/dev/null
        install -m 755 "$tmp/anytls-server" /usr/local/bin/anytls-server
        install -m 755 "$tmp/anytls-client" /usr/local/bin/anytls-client
        rm -rf "$tmp"
        _ok "AnyTLS 已安装"
    else
        rm -rf "$tmp"; _err "下载 AnyTLS 失败"; return 1
    fi
}

# 安装 TUIC (服务端和客户端)
install_tuic() {
    local role="${1:-server}"
    local bin_path bin_name
    
    if [[ "$role" == "server" ]]; then
        bin_name="tuic-server"
        bin_path="/usr/local/bin/tuic-server"
    else
        bin_name="tuic-client"
        bin_path="/usr/local/bin/tuic-client"
    fi
    
    # 检查是否已安装且为有效的 ELF 文件
    if [[ -x "$bin_path" ]] && file "$bin_path" 2>/dev/null | grep -qE "ELF.*executable"; then
        _ok "$bin_name 已安装"
        return 0
    fi
    
    # 删除可能存在的损坏文件
    [[ -f "$bin_path" ]] && rm -f "$bin_path"
    
    local arch=$(uname -m) tarch
    case $arch in
        x86_64)  tarch="x86_64-unknown-linux-gnu" ;;
        aarch64) tarch="aarch64-unknown-linux-gnu" ;;
        armv7l)  tarch="armv7-unknown-linux-gnueabihf" ;;
        *) _err "不支持的架构: $arch"; return 1 ;;
    esac

    _info "安装 TUIC v5..."
    local tmp=$(mktemp -d)
    local download_url
    
    if [[ "$role" == "server" ]]; then
        download_url="https://github.com/EAimTY/tuic/releases/download/tuic-server-1.0.0/tuic-server-1.0.0-${tarch}"
    else
        download_url="https://github.com/EAimTY/tuic/releases/download/tuic-client-1.0.0/tuic-client-1.0.0-${tarch}"
    fi
    
    _info "下载 $bin_name..."
    if curl -fSL -o "$tmp/$bin_name" --connect-timeout 30 --retry 3 "$download_url" 2>/dev/null; then
        # 验证下载的文件是否为 ELF 二进制
        if file "$tmp/$bin_name" 2>/dev/null | grep -qE "ELF.*executable"; then
            install -m 755 "$tmp/$bin_name" "$bin_path"
            rm -rf "$tmp"
            _ok "$bin_name 已安装"
            return 0
        else
            _err "下载的文件不是有效的可执行文件"
            rm -rf "$tmp"
            return 1
        fi
    else
        rm -rf "$tmp"
        _err "下载 $bin_name 失败"
        return 1
    fi
}

# 生成通用自签名证书 (适配 Xray/Hysteria/Trojan)
gen_self_cert() {
    local domain="${1:-localhost}"
    mkdir -p "$CFG/certs"
    rm -f "$CFG/certs/server.crt" "$CFG/certs/server.key"
    
    _info "生成自签名证书..."
    # Xray/Go 需要标准的自签名证书 (隐含 CA:TRUE)
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout "$CFG/certs/server.key" -out "$CFG/certs/server.crt" \
        -subj "/CN=$domain" -days 36500 2>/dev/null
    
    chmod 600 "$CFG/certs/server.key"
}


#═══════════════════════════════════════════════════════════════════════════════
# 配置生成
#═══════════════════════════════════════════════════════════════════════════════

# VLESS+Reality 服务端配置
gen_server_config() {
    local uuid="$1" port="$2" privkey="$3" pubkey="$4" sid="$5" sni="$6"
    mkdir -p "$CFG"

    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件 (供 generate_xray_config 读取)
    cat > "$CFG/vless.info" << EOF
protocol=vless
uuid=$uuid
port=$port
private_key=$privkey
public_key=$pubkey
short_id=$sid
sni=$sni
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 注册协议
    register_protocol "vless"

    # 保存 join 信息
    > "$CFG/vless.join"
    if [[ -n "$ipv4" ]]; then
        local data="REALITY|$ipv4|$port|$uuid|$pubkey|$sid|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_vless_link "$ipv4" "$port" "$uuid" "$pubkey" "$sid" "$sni")
        printf '%s\n' "# IPv4" >> "$CFG/vless.join"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/vless.join"
        printf '%s\n' "VLESS_V4=$link" >> "$CFG/vless.join"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="REALITY|[$ipv6]|$port|$uuid|$pubkey|$sid|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_vless_link "[$ipv6]" "$port" "$uuid" "$pubkey" "$sid" "$sni")
        printf '%s\n' "# IPv6" >> "$CFG/vless.join"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/vless.join"
        printf '%s\n' "VLESS_V6=$link" >> "$CFG/vless.join"
    fi
    echo "server" > "$CFG/role"
}

# VLESS+Reality+XHTTP 服务端配置
gen_vless_xhttp_server_config() {
    local uuid="$1" port="$2" privkey="$3" pubkey="$4" sid="$5" sni="$6" path="${7:-/}"
    mkdir -p "$CFG"
    
    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件 (供 generate_xray_config 读取)
    cat > "$CFG/vless-xhttp.info" << EOF
protocol=vless-xhttp
uuid=$uuid
port=$port
private_key=$privkey
public_key=$pubkey
short_id=$sid
sni=$sni
path=$path
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 注册协议
    register_protocol "vless-xhttp"

    # 保存 join 信息
    > "$CFG/vless-xhttp.join"
    if [[ -n "$ipv4" ]]; then
        local data="REALITY-XHTTP|$ipv4|$port|$uuid|$pubkey|$sid|$sni|$path"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_vless_xhttp_link "$ipv4" "$port" "$uuid" "$pubkey" "$sid" "$sni" "$path")
        printf '%s\n' "# IPv4" >> "$CFG/vless-xhttp.join"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/vless-xhttp.join"
        printf '%s\n' "VLESS_XHTTP_V4=$link" >> "$CFG/vless-xhttp.join"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="REALITY-XHTTP|[$ipv6]|$port|$uuid|$pubkey|$sid|$sni|$path"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_vless_xhttp_link "[$ipv6]" "$port" "$uuid" "$pubkey" "$sid" "$sni" "$path")
        printf '%s\n' "# IPv6" >> "$CFG/vless-xhttp.join"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/vless-xhttp.join"
        printf '%s\n' "VLESS_XHTTP_V6=$link" >> "$CFG/vless-xhttp.join"
    fi
    echo "server" > "$CFG/role"
}

# Hysteria2 服务端配置
gen_hy2_server_config() {
    local password="$1" port="$2" sni="${3:-bing.com}"
    mkdir -p "$CFG"
    gen_self_cert "$sni"

    cat > "$CFG/hy2.yaml" << EOF
listen: :$port

tls:
  cert: $CFG/certs/server.crt
  key: $CFG/certs/server.key

auth:
  type: password
  password: $password

masquerade:
  type: proxy
  proxy:
    url: https://bing.com
    rewriteHost: true

bandwidth:
  up: 1 gbps
  down: 1 gbps
EOF
    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件
    cat > "$CFG/hy2.info" << EOF
protocol=hy2
password=$password
port=$port
sni=$sni
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 兼容性：也保存到主 info 文件
    cp "$CFG/hy2.info" "$CFG/info"
    
    # 注册协议
    register_protocol "hy2"

    > "$CFG/join.txt"
    if [[ -n "$ipv4" ]]; then
        local data="HY2|$ipv4|$port|$password|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_hy2_link "$ipv4" "$port" "$password" "$sni")
        printf '%s\n' "# IPv4" >> "$CFG/join.txt"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/join.txt"
        printf '%s\n' "HY2_V4=$link" >> "$CFG/join.txt"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="HY2|[$ipv6]|$port|$password|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_hy2_link "[$ipv6]" "$port" "$password" "$sni")
        printf '%s\n' "# IPv6" >> "$CFG/join.txt"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/join.txt"
        printf '%s\n' "HY2_V6=$link" >> "$CFG/join.txt"
    fi
    echo "server" > "$CFG/role"
    echo "hy2" > "$CFG/protocol"
}

# Trojan 服务端配置
gen_trojan_server_config() {
    local password="$1" port="$2" sni="${3:-bing.com}"
    mkdir -p "$CFG"
    gen_self_cert "$sni"

    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件 (供 generate_xray_config 读取)
    cat > "$CFG/trojan.info" << EOF
protocol=trojan
password=$password
port=$port
sni=$sni
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 注册协议
    register_protocol "trojan"

    # 保存 join 信息
    > "$CFG/trojan.join"
    if [[ -n "$ipv4" ]]; then
        local data="TROJAN|$ipv4|$port|$password|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_trojan_link "$ipv4" "$port" "$password" "$sni")
        printf '%s\n' "# IPv4" >> "$CFG/trojan.join"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/trojan.join"
        printf '%s\n' "TROJAN_V4=$link" >> "$CFG/trojan.join"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="TROJAN|[$ipv6]|$port|$password|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_trojan_link "[$ipv6]" "$port" "$password" "$sni")
        printf '%s\n' "# IPv6" >> "$CFG/trojan.join"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/trojan.join"
        printf '%s\n' "TROJAN_V6=$link" >> "$CFG/trojan.join"
    fi
    echo "server" > "$CFG/role"
}

# VLESS+WS+TLS 服务端配置
gen_vless_ws_server_config() {
    local uuid="$1" port="$2" sni="${3:-bing.com}" path="${4:-/vless}"
    mkdir -p "$CFG"
    gen_self_cert "$sni"

    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件 (供 generate_xray_config 读取)
    cat > "$CFG/vless-ws.info" << EOF
protocol=vless-ws
uuid=$uuid
port=$port
sni=$sni
path=$path
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 注册协议
    register_protocol "vless-ws"

    # 保存 join 信息
    > "$CFG/vless-ws.join"
    if [[ -n "$ipv4" ]]; then
        local data="VLESS-WS|$ipv4|$port|$uuid|$sni|$path"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_vless_ws_link "$ipv4" "$port" "$uuid" "$sni" "$path")
        printf '%s\n' "# IPv4" >> "$CFG/vless-ws.join"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/vless-ws.join"
        printf '%s\n' "VLESS_WS_V4=$link" >> "$CFG/vless-ws.join"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="VLESS-WS|[$ipv6]|$port|$uuid|$sni|$path"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_vless_ws_link "[$ipv6]" "$port" "$uuid" "$sni" "$path")
        printf '%s\n' "# IPv6" >> "$CFG/vless-ws.join"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/vless-ws.join"
        printf '%s\n' "VLESS_WS_V6=$link" >> "$CFG/vless-ws.join"
    fi
    echo "server" > "$CFG/role"
}

# VLESS-XTLS-Vision 服务端配置
gen_vless_vision_server_config() {
    local uuid="$1" port="$2" sni="${3:-bing.com}"
    mkdir -p "$CFG"
    gen_self_cert "$sni"

    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件 (供 generate_xray_config 读取)
    cat > "$CFG/vless-vision.info" << EOF
protocol=vless-vision
uuid=$uuid
port=$port
sni=$sni
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 注册协议
    register_protocol "vless-vision"

    # 保存 join 信息
    > "$CFG/vless-vision.join"
    if [[ -n "$ipv4" ]]; then
        local data="VLESS-VISION|$ipv4|$port|$uuid|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_vless_vision_link "$ipv4" "$port" "$uuid" "$sni")
        printf '%s\n' "# IPv4" >> "$CFG/vless-vision.join"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/vless-vision.join"
        printf '%s\n' "VLESS_VISION_V4=$link" >> "$CFG/vless-vision.join"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="VLESS-VISION|[$ipv6]|$port|$uuid|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_vless_vision_link "[$ipv6]" "$port" "$uuid" "$sni")
        printf '%s\n' "# IPv6" >> "$CFG/vless-vision.join"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/vless-vision.join"
        printf '%s\n' "VLESS_VISION_V6=$link" >> "$CFG/vless-vision.join"
    fi
    echo "server" > "$CFG/role"
}

# Shadowsocks 2022 服务端配置
gen_ss2022_server_config() {
    local password="$1" port="$2" method="${3:-2022-blake3-aes-128-gcm}"
    mkdir -p "$CFG"

    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件 (供 generate_xray_config 读取)
    cat > "$CFG/ss2022.info" << EOF
protocol=ss2022
password=$password
port=$port
method=$method
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 注册协议
    register_protocol "ss2022"

    # 保存 join 信息
    > "$CFG/ss2022.join"
    if [[ -n "$ipv4" ]]; then
        local data="SS2022|$ipv4|$port|$method|$password"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_ss2022_link "$ipv4" "$port" "$method" "$password")
        printf '%s\n' "# IPv4" >> "$CFG/ss2022.join"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/ss2022.join"
        printf '%s\n' "SS2022_V4=$link" >> "$CFG/ss2022.join"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="SS2022|[$ipv6]|$port|$method|$password"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_ss2022_link "[$ipv6]" "$port" "$method" "$password")
        printf '%s\n' "# IPv6" >> "$CFG/ss2022.join"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/ss2022.join"
        printf '%s\n' "SS2022_V6=$link" >> "$CFG/ss2022.join"
    fi
    echo "server" > "$CFG/role"
}

# Snell v4 服务端配置
gen_snell_server_config() {
    local psk="$1" port="$2" version="${3:-4}"
    mkdir -p "$CFG"

    cat > "$CFG/config.conf" << EOF
[snell-server]
listen = 0.0.0.0:$port
psk = $psk
ipv6 = true
obfs = off
EOF
    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件
    cat > "$CFG/snell.info" << EOF
protocol=snell
psk=$psk
port=$port
version=$version
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 兼容性：也保存到主 info 文件
    cp "$CFG/snell.info" "$CFG/info"
    
    # 注册协议
    register_protocol "snell"

    > "$CFG/join.txt"
    if [[ -n "$ipv4" ]]; then
        local data="SNELL|$ipv4|$port|$psk|$version"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_snell_link "$ipv4" "$port" "$psk" "$version")
        printf '%s\n' "# IPv4" >> "$CFG/join.txt"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/join.txt"
        printf '%s\n' "SNELL_V4=$link" >> "$CFG/join.txt"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="SNELL|[$ipv6]|$port|$psk|$version"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_snell_link "[$ipv6]" "$port" "$psk" "$version")
        printf '%s\n' "# IPv6" >> "$CFG/join.txt"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/join.txt"
        printf '%s\n' "SNELL_V6=$link" >> "$CFG/join.txt"
    fi
    echo "server" > "$CFG/role"
    echo "snell" > "$CFG/protocol"
}

# TUIC v5 服务端配置
gen_tuic_server_config() {
    local uuid="$1" password="$2" port="$3" sni="${4:-bing.com}"
    mkdir -p "$CFG"
    
    # === TUIC 专用证书生成 (严格模式 CA:FALSE) ===
    local server_ip=$(get_ipv4)
    [[ -z "$server_ip" ]] && server_ip=$(get_ipv6)
    [[ -z "$server_ip" ]] && server_ip="$sni"
    
    mkdir -p "$CFG/certs"
    rm -f "$CFG/certs/server.crt" "$CFG/certs/server.key"
    
    _info "生成 TUIC 专用证书..."
    # 强制指定 CA:FALSE 和 serverAuth
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout "$CFG/certs/server.key" -out "$CFG/certs/server.crt" \
        -subj "/CN=$server_ip" -days 36500 \
        -addext "subjectAltName=DNS:$server_ip,IP:$server_ip" \
        -addext "basicConstraints=critical,CA:FALSE" \
        -addext "extendedKeyUsage=serverAuth" 2>/dev/null
    
    chmod 600 "$CFG/certs/server.key"
    # ==========================================

    cat > "$CFG/config.json" << EOF
{
    "server": "[::]:$port",
    "users": {
        "$uuid": "$password"
    },
    "certificate": "$CFG/certs/server.crt",
    "private_key": "$CFG/certs/server.key",
    "congestion_control": "bbr",
    "alpn": ["h3"],
    "zero_rtt_handshake": false,
    "auth_timeout": "3s",
    "max_idle_time": "10s",
    "max_external_packet_size": 1500,
    "gc_interval": "3s",
    "gc_lifetime": "15s",
    "log_level": "warn"
}
EOF
    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件
    cat > "$CFG/tuic.info" << EOF
protocol=tuic
uuid=$uuid
password=$password
port=$port
sni=$sni
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 兼容性：也保存到主 info 文件
    cp "$CFG/tuic.info" "$CFG/info"
    
    # 注册协议
    register_protocol "tuic"

    > "$CFG/join.txt"
    if [[ -n "$ipv4" ]]; then
        local data="TUIC|$ipv4|$port|$uuid|$password|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_tuic_link "$ipv4" "$port" "$uuid" "$password" "$sni")
        printf '%s\n' "# IPv4" >> "$CFG/join.txt"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/join.txt"
        printf '%s\n' "TUIC_V4=$link" >> "$CFG/join.txt"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="TUIC|[$ipv6]|$port|$uuid|$password|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_tuic_link "[$ipv6]" "$port" "$uuid" "$password" "$sni")
        printf '%s\n' "# IPv6" >> "$CFG/join.txt"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/join.txt"
        printf '%s\n' "TUIC_V6=$link" >> "$CFG/join.txt"
    fi
    echo "server" > "$CFG/role"
    echo "tuic" > "$CFG/protocol"
}

# AnyTLS 服务端配置
gen_anytls_server_config() {
    local password="$1" port="$2" sni="${3:-bing.com}"
    mkdir -p "$CFG"
    # AnyTLS 不需要配置文件，使用命令行参数
    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件
    cat > "$CFG/anytls.info" << EOF
protocol=anytls
password=$password
port=$port
sni=$sni
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 兼容性：也保存到主 info 文件
    cp "$CFG/anytls.info" "$CFG/info"
    
    # 注册协议
    register_protocol "anytls"

    > "$CFG/join.txt"
    if [[ -n "$ipv4" ]]; then
        local data="ANYTLS|$ipv4|$port|$password|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_anytls_link "$ipv4" "$port" "$password" "$sni")
        printf '%s\n' "# IPv4" >> "$CFG/join.txt"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/join.txt"
        printf '%s\n' "ANYTLS_V4=$link" >> "$CFG/join.txt"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="ANYTLS|[$ipv6]|$port|$password|$sni"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_anytls_link "[$ipv6]" "$port" "$password" "$sni")
        printf '%s\n' "# IPv6" >> "$CFG/join.txt"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/join.txt"
        printf '%s\n' "ANYTLS_V6=$link" >> "$CFG/join.txt"
    fi
    echo "server" > "$CFG/role"
    echo "anytls" > "$CFG/protocol"
}

# SOCKS5 服务端配置
gen_socks_server_config() {
    local username="$1" password="$2" port="$3"
    mkdir -p "$CFG"

    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件 (供 generate_xray_config 读取)
    cat > "$CFG/socks.info" << EOF
protocol=socks
username=$username
password=$password
port=$port
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 注册协议
    register_protocol "socks"

    # 保存 join 信息
    > "$CFG/socks.join"
    if [[ -n "$ipv4" ]]; then
        local data="SOCKS|$ipv4|$port|$username|$password"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local tg_link=$(gen_socks_link "$ipv4" "$port" "$username" "$password")
        local socks_link="socks5://${username}:${password}@${ipv4}:${port}#SOCKS5-${ipv4}"
        printf '%s\n' "# IPv4" >> "$CFG/socks.join"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/socks.join"
        printf '%s\n' "SOCKS_V4=$tg_link" >> "$CFG/socks.join"
        printf '%s\n' "SOCKS5_V4=$socks_link" >> "$CFG/socks.join"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="SOCKS|[$ipv6]|$port|$username|$password"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local tg_link="https://t.me/socks?server=[$ipv6]&port=${port}&user=${username}&pass=${password}"
        local socks_link="socks5://${username}:${password}@[$ipv6]:${port}#SOCKS5-[$ipv6]"
        printf '%s\n' "# IPv6" >> "$CFG/socks.join"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/socks.join"
        printf '%s\n' "SOCKS_V6=$tg_link" >> "$CFG/socks.join"
        printf '%s\n' "SOCKS5_V6=$socks_link" >> "$CFG/socks.join"
    fi
    echo "server" > "$CFG/role"
}

# Snell v5 服务端配置
gen_snell_v5_server_config() {
    local psk="$1" port="$2" version="${3:-5}"
    mkdir -p "$CFG"

    cat > "$CFG/config.conf" << EOF
[snell-server]
listen = 0.0.0.0:$port
psk = $psk
version = $version
ipv6 = true
obfs = off
EOF
    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    
    # 保存到独立的 info 文件
    cat > "$CFG/snell-v5.info" << EOF
protocol=snell-v5
psk=$psk
port=$port
version=$version
ipv4=$ipv4
ipv6=$ipv6
EOF
    
    # 兼容性：也保存到主 info 文件
    cp "$CFG/snell-v5.info" "$CFG/info"
    
    # 注册协议
    register_protocol "snell-v5"

    > "$CFG/join.txt"
    if [[ -n "$ipv4" ]]; then
        local data="SNELL-V5|$ipv4|$port|$psk|$version"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_snell_v5_link "$ipv4" "$port" "$psk" "$version")
        printf '%s\n' "# IPv4" >> "$CFG/join.txt"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/join.txt"
        printf '%s\n' "SNELL_V5_V4=$link" >> "$CFG/join.txt"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="SNELL-V5|[$ipv6]|$port|$psk|$version"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local link=$(gen_snell_v5_link "[$ipv6]" "$port" "$psk" "$version")
        printf '%s\n' "# IPv6" >> "$CFG/join.txt"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/join.txt"
        printf '%s\n' "SNELL_V5_V6=$link" >> "$CFG/join.txt"
    fi
    echo "server" > "$CFG/role"
    echo "snell-v5" > "$CFG/protocol"
}

#═══════════════════════════════════════════════════════════════════════════════
# 客户端配置生成 (支持所有协议)
#═══════════════════════════════════════════════════════════════════════════════
gen_client_config() {
    local protocol_type="$1"
    shift
    local mode=$(get_mode)
    mkdir -p "$CFG"

    local inbounds='[{"port": '$SOCKS_PORT', "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": true}}]'
    [[ "$mode" == "global" ]] && inbounds='[
        {"port": '$SOCKS_PORT', "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": true}},
        {"port": '$REDIR_PORT', "listen": "::", "protocol": "dokodemo-door", "settings": {"network": "tcp,udp", "followRedirect": true}, "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}}
    ]'

    local sockopt_json=""
    if [[ "$mode" == "tun" ]]; then
        sockopt_json='"sockopt": {"mark": '$FWMARK', "tcpKeepAliveIdle": 100},'
    fi

    case "$protocol_type" in
        vless)
            # 参数: ip port uuid pubkey sid sni
            local ip="$1" port="$2" uuid="$3" pubkey="$4" sid="$5" sni="$6"
            cat > "$CFG/config.json" << EOF
{
    "log": {"loglevel": "warning"},
    "inbounds": $inbounds,
    "outbounds": [{
        "protocol": "vless",
        "settings": {"vnext": [{"address": "$ip", "port": $port, "users": [{"id": "$uuid", "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
        "streamSettings": {
            $sockopt_json
            "network": "tcp", "security": "reality",
            "realitySettings": {"show": false, "fingerprint": "chrome", "serverName": "$sni", "publicKey": "$pubkey", "shortId": "$sid", "spiderX": ""}
        }
    }]
}
EOF
            cat > "$CFG/info" << EOF
protocol=vless
server_ip=$ip
port=$port
uuid=$uuid
public_key=$pubkey
short_id=$sid
sni=$sni
EOF
            ;;
        vless-xhttp)
            # 参数: ip port uuid pubkey sid sni path
            local ip="$1" port="$2" uuid="$3" pubkey="$4" sid="$5" sni="$6" path="${7:-/}"
            cat > "$CFG/config.json" << EOF
{
    "log": {"loglevel": "warning"},
    "inbounds": $inbounds,
    "outbounds": [{
        "protocol": "vless",
        "settings": {"vnext": [{"address": "$ip", "port": $port, "users": [{"id": "$uuid", "encryption": "none"}]}]},
        "streamSettings": {
            $sockopt_json
            "network": "xhttp",
            "xhttpSettings": {"path": "$path", "mode": "auto"},
            "security": "reality",
            "realitySettings": {"show": false, "fingerprint": "chrome", "serverName": "$sni", "publicKey": "$pubkey", "shortId": "$sid", "spiderX": ""}
        }
    }]
}
EOF
            cat > "$CFG/info" << EOF
protocol=vless-xhttp
server_ip=$ip
port=$port
uuid=$uuid
public_key=$pubkey
short_id=$sid
sni=$sni
path=$path
EOF
            ;;
        vless-ws)
            # 参数: ip port uuid sni path
            local ip="$1" port="$2" uuid="$3" sni="$4" path="${5:-/vless}"
            cat > "$CFG/config.json" << EOF
{
    "log": {"loglevel": "warning"},
    "inbounds": $inbounds,
    "outbounds": [{
        "protocol": "vless",
        "settings": {"vnext": [{"address": "$ip", "port": $port, "users": [{"id": "$uuid", "encryption": "none"}]}]},
        "streamSettings": {
            $sockopt_json
            "network": "ws",
            "security": "tls",
            "tlsSettings": {"allowInsecure": true, "serverName": "$sni"},
            "wsSettings": {"path": "$path", "headers": {"Host": "$sni"}}
        }
    }]
}
EOF
            cat > "$CFG/info" << EOF
protocol=vless-ws
server_ip=$ip
port=$port
uuid=$uuid
sni=$sni
path=$path
EOF
            ;;
        vless-vision)
            # 参数: ip port uuid sni
            local ip="$1" port="$2" uuid="$3" sni="$4"
            cat > "$CFG/config.json" << EOF
{
    "log": {"loglevel": "warning"},
    "inbounds": $inbounds,
    "outbounds": [{
        "protocol": "vless",
        "settings": {"vnext": [{"address": "$ip", "port": $port, "users": [{"id": "$uuid", "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
        "streamSettings": {
            $sockopt_json
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {"allowInsecure": true, "serverName": "$sni", "alpn": ["h2", "http/1.1"]}
        }
    }]
}
EOF
            cat > "$CFG/info" << EOF
protocol=vless-vision
server_ip=$ip
port=$port
uuid=$uuid
sni=$sni
EOF
            ;;
        socks)
            # 参数: ip port username password
            local ip="$1" port="$2" username="$3" password="$4"
            cat > "$CFG/config.json" << EOF
{
    "log": {"loglevel": "warning"},
    "inbounds": $inbounds,
    "outbounds": [{
        "protocol": "socks",
        "settings": {"servers": [{"address": "$ip", "port": $port, "users": [{"user": "$username", "pass": "$password"}]}]}
    }]
}
EOF
            cat > "$CFG/info" << EOF
protocol=socks
server_ip=$ip
port=$port
username=$username
password=$password
EOF
            ;;
        ss2022)
            # 参数: ip port method password
            local ip="$1" port="$2" method="$3" password="$4"
            cat > "$CFG/config.json" << EOF
{
    "log": {"loglevel": "warning"},
    "inbounds": $inbounds,
    "outbounds": [{
        "protocol": "shadowsocks",
        "settings": {"servers": [{"address": "$ip", "port": $port, "method": "$method", "password": "$password"}]}
    }]
}
EOF
            cat > "$CFG/info" << EOF
protocol=ss2022
server_ip=$ip
port=$port
method=$method
password=$password
EOF
            ;;
        trojan)
            # 参数: ip port password sni
            local ip="$1" port="$2" password="$3" sni="$4"
            cat > "$CFG/config.json" << EOF
{
    "log": {"loglevel": "warning"},
    "inbounds": $inbounds,
    "outbounds": [{
        "protocol": "trojan",
        "settings": {"servers": [{"address": "$ip", "port": $port, "password": "$password"}]},
        "streamSettings": {
            $sockopt_json
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {"allowInsecure": true, "serverName": "$sni"}
        }
    }]
}
EOF
            cat > "$CFG/info" << EOF
protocol=trojan
server_ip=$ip
port=$port
password=$password
sni=$sni
EOF
            ;;
        hy2)
            # 参数: ip port password sni
            local ip="$1" port="$2" password="$3" sni="$4"
            cat > "$CFG/hy2.yaml" << EOF
server: $ip:$port
auth: $password
tls:
  sni: $sni
  insecure: true
socks5:
  listen: 127.0.0.1:$SOCKS_PORT
EOF
            cat > "$CFG/info" << EOF
protocol=hy2
server_ip=$ip
port=$port
password=$password
sni=$sni
EOF
            ;;
        snell)
            # 参数: ip port psk version
            local ip="$1" port="$2" psk="$3" version="${4:-4}"
            # Snell 客户端配置 (用于 Surge/Clash)
            cat > "$CFG/config.conf" << EOF
[snell-client]
server = $ip
port = $port
psk = $psk
version = $version
EOF
            cat > "$CFG/info" << EOF
protocol=snell
server_ip=$ip
port=$port
psk=$psk
version=$version
EOF
            _warn "Snell 客户端需要 Surge/Clash 等软件支持"
            ;;
        tuic)
            # 参数: ip port uuid password sni [cert_path]
            local ip="$1" port="$2" uuid="$3" password="$4" sni="$5" cert_path="${6:-}"
            local clean_ip=$(echo "$ip" | tr -d '[]')
            
            # 如果没有传入证书路径，使用默认路径
            if [[ -z "$cert_path" ]]; then
                cert_path="$CFG/certs/server.crt"
            fi
            
            cat > "$CFG/config.json" << EOF
{
    "relay": {
        "server": "$clean_ip:$port",
        "uuid": "$uuid",
        "password": "$password",
        "congestion_control": "bbr",
        "alpn": ["h3"],
        "udp_relay_mode": "native",
        "zero_rtt_handshake": false,
        "certificates": ["$cert_path"]
    },
    "local": {
        "server": "127.0.0.1:$SOCKS_PORT"
    },
    "log_level": "info"
}
EOF
            cat > "$CFG/info" << EOF
protocol=tuic
server_ip=$ip
port=$port
uuid=$uuid
password=$password
sni=$sni
cert_path=$cert_path
EOF
            ;;
        anytls)
            # 参数: ip port password sni
            local ip="$1" port="$2" password="$3" sni="$4"
            # AnyTLS 不需要配置文件，使用命令行参数
            cat > "$CFG/info" << EOF
protocol=anytls
server_ip=$ip
port=$port
password=$password
sni=$sni
EOF
            ;;
        snell-v5)
            # 参数: ip port psk version
            local ip="$1" port="$2" psk="$3" version="${4:-5}"
            # Snell v5 客户端配置 (用于 Surge/Clash)
            cat > "$CFG/config.conf" << EOF
[snell-client]
server = $ip
port = $port
psk = $psk
version = $version
EOF
            cat > "$CFG/info" << EOF
protocol=snell-v5
server_ip=$ip
port=$port
psk=$psk
version=$version
EOF
            _warn "Snell v5 客户端需要 Surge/Clash 等软件支持"
            ;;
    esac
    
    echo "client" > "$CFG/role"
    echo "$protocol_type" > "$CFG/protocol"
    
    # 客户端也需要注册协议
    register_protocol "$protocol_type"
}

#═══════════════════════════════════════════════════════════════════════════════
# 辅助脚本生成
#═══════════════════════════════════════════════════════════════════════════════
create_scripts() {
    cat > "$CFG/tun-up.sh" << EOFSCRIPT
#!/bin/bash
set -e
CFG="/etc/vless-reality"
TUN_IP="$TUN_IP"; TUN_GW="$TUN_GW"
FWMARK="$FWMARK"

ip link del tun0 2>/dev/null || true
ip route flush table 55 2>/dev/null || true
while ip rule show | grep -q "lookup 55"; do ip rule del lookup 55 2>/dev/null || true; done

mkdir -p /dev/net
[[ ! -c /dev/net/tun ]] && mknod /dev/net/tun c 10 200 2>/dev/null || true
echo 1 > /proc/sys/net/ipv4/ip_forward
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "\$f"; done

DEF_GW=\$(ip -4 route show default | grep default | head -1 | awk '{print \$3}')
DEF_DEV=\$(ip -4 route show default | grep default | head -1 | awk '{print \$5}')
LOCAL_IP=\$(ip -4 addr show dev "\$DEF_DEV" | grep "inet " | awk '{print \$2}' | cut -d/ -f1 | head -1)

if [[ -z "\$DEF_GW" || -z "\$DEF_DEV" || -z "\$LOCAL_IP" ]]; then echo "错误：无法获取物理网络信息"; exit 1; fi
echo "\$DEF_GW|\$DEF_DEV|\$LOCAL_IP" > /tmp/vless-tun-info

ip tuntap add mode tun dev tun0
ip link set dev tun0 up mtu 1280
ip -4 addr add \$TUN_IP/30 dev tun0

ip route add default via "\$DEF_GW" dev "\$DEF_DEV" table 55
ip rule add fwmark \$FWMARK lookup 55 pref 900
ip rule add from "\$LOCAL_IP" lookup 55 pref 1000

SERVER_IP=\$(grep "server_ip=" "\$CFG/info" | cut -d= -f2)
if [[ -n "\$SERVER_IP" ]]; then
    if [[ ! "\$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
         RESOLVED_IP=\$(getent ahostsv4 "\$SERVER_IP" | awk '{print \$1}' | head -1)
         [[ -n "\$RESOLVED_IP" ]] && SERVER_IP="\$RESOLVED_IP"
    fi
    ip -4 route add "\$SERVER_IP" via "\$DEF_GW" dev "\$DEF_DEV" 2>/dev/null || true
    echo "\$SERVER_IP" > /tmp/vless-tun-routes
fi

ip -4 route add 0.0.0.0/1 via \$TUN_GW dev tun0
ip -4 route add 128.0.0.0/1 via \$TUN_GW dev tun0
echo "TUN 模式启动成功"
EOFSCRIPT

    cat > "$CFG/tun-down.sh" << EOFSCRIPT
#!/bin/bash
CFG="/etc/vless-reality"
TUN_GW="$TUN_GW"
FWMARK="$FWMARK"

ip -4 route del 0.0.0.0/1 via \$TUN_GW dev tun0 2>/dev/null || true
ip -4 route del 128.0.0.0/1 via \$TUN_GW dev tun0 2>/dev/null || true

if [[ -f /tmp/vless-tun-info ]]; then
    IFS='|' read -r DEF_GW DEF_DEV LOCAL_IP < /tmp/vless-tun-info
    ip rule del fwmark \$FWMARK lookup 55 2>/dev/null || true
    if [[ -n "\$LOCAL_IP" ]]; then ip rule del from "\$LOCAL_IP" lookup 55 2>/dev/null || true; fi
    ip route flush table 55 2>/dev/null || true
    if [[ -f /tmp/vless-tun-routes ]]; then
        while read -r ip; do
            [[ -n "\$ip" ]] && { ip -4 route del "\$ip" via "\$DEF_GW" dev "\$DEF_DEV" 2>/dev/null || true; }
        done < /tmp/vless-tun-routes
    fi
    rm -f /tmp/vless-tun-info /tmp/vless-tun-routes
fi
ip link del tun0 2>/dev/null || true
echo "TUN 已停止"
EOFSCRIPT

    cat > "$CFG/watchdog.sh" << 'EOFSCRIPT'
#!/bin/bash
CFG="/etc/vless-reality"
LOG_FILE="/var/log/vless-watchdog.log"
FAIL_COUNT=0
MAX_FAIL=3

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"; }

# 获取当前协议对应的服务名和进程名
get_service_info() {
    local proto=$(cat "$CFG/protocol" 2>/dev/null)
    case "$proto" in
        vless|vless-xhttp|vless-ws|vless-vision|trojan|socks|ss2022)
            echo "vless-reality xray"
            ;;
        hy2)
            echo "vless-hy2 hysteria"
            ;;
        tuic)
            echo "vless-tuic tuic-client"
            ;;
        snell)
            echo "vless-snell snell-server"
            ;;
        snell-v5)
            echo "vless-snell-v5 snell-server-v5"
            ;;
        anytls)
            echo "vless-anytls anytls-client"
            ;;
        *)
            echo "vless-reality xray"
            ;;
    esac
}

read SERVICE_NAME PROC_NAME <<< $(get_service_info)

while true; do
    if ! pgrep -x "$PROC_NAME" > /dev/null; then
        log "CRITICAL: $PROC_NAME process dead. Restarting..."
        systemctl restart "$SERVICE_NAME"
        sleep 10
        continue
    fi
    if curl -x socks5://127.0.0.1:10808 -s --connect-timeout 5 https://www.cloudflare.com > /dev/null; then
        FAIL_COUNT=0
    else
        FAIL_COUNT=$((FAIL_COUNT+1))
        log "WARNING: Connection failed ($FAIL_COUNT/$MAX_FAIL)"
    fi
    if [[ $FAIL_COUNT -ge $MAX_FAIL ]]; then
        log "ERROR: Max failures reached. Restarting services..."
        if [[ -f "$CFG/mode" && "$(cat "$CFG/mode")" == "tun" ]]; then
             systemctl restart vless-tun
        fi
        systemctl restart "$SERVICE_NAME"
        FAIL_COUNT=0
        sleep 20
    fi
    sleep 60
done
EOFSCRIPT

    cat > "$CFG/global-up.sh" << 'EOFSCRIPT'
#!/bin/bash
CFG="/etc/vless-reality"; REDIR_PORT=10809

# 从 info 文件读取服务器 IP（兼容所有协议）
if [[ -f "$CFG/info" ]]; then
    PROXY_HOST=$(grep "^server_ip=" "$CFG/info" | cut -d'=' -f2 | tr -d '[]')
else
    # 回退到 Xray 配置格式
    PROXY_HOST=$(jq -r '.outbounds[0].settings.vnext[0].address // .outbounds[0].settings.servers[0].address // empty' "$CFG/config.json" 2>/dev/null)
fi

[[ -z "$PROXY_HOST" ]] && { echo "无法获取服务器地址"; exit 1; }

PROXY_IP4=$(getent ahostsv4 "$PROXY_HOST" 2>/dev/null | awk '{print $1}' | sort -u || echo "$PROXY_HOST")
PROXY_IP6=$(getent ahostsv6 "$PROXY_HOST" 2>/dev/null | awk '{print $1}' | sort -u)
iptables -t nat -F VLESS_PROXY 2>/dev/null; iptables -t nat -X VLESS_PROXY 2>/dev/null; iptables -t nat -N VLESS_PROXY
for cidr in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do iptables -t nat -A VLESS_PROXY -d $cidr -j RETURN; done
for ip in $PROXY_IP4; do iptables -t nat -A VLESS_PROXY -d "$ip" -j RETURN; done
iptables -t nat -A VLESS_PROXY -p tcp -j REDIRECT --to-ports $REDIR_PORT
iptables -t nat -D OUTPUT -p tcp -j VLESS_PROXY 2>/dev/null; iptables -t nat -A OUTPUT -p tcp -j VLESS_PROXY
ip6tables -t nat -F VLESS_PROXY 2>/dev/null; ip6tables -t nat -X VLESS_PROXY 2>/dev/null; ip6tables -t nat -N VLESS_PROXY
for cidr in ::1/128 fe80::/10 fc00::/7; do ip6tables -t nat -A VLESS_PROXY -d $cidr -j RETURN; done
for ip in $PROXY_IP6; do ip6tables -t nat -A VLESS_PROXY -d "$ip" -j RETURN; done
ip6tables -t nat -A VLESS_PROXY -p tcp -j REDIRECT --to-ports $REDIR_PORT
ip6tables -t nat -D OUTPUT -p tcp -j VLESS_PROXY 2>/dev/null; ip6tables -t nat -A OUTPUT -p tcp -j VLESS_PROXY
EOFSCRIPT

    cat > "$CFG/global-down.sh" << 'EOFSCRIPT'
#!/bin/bash
iptables -t nat -D OUTPUT -p tcp -j VLESS_PROXY 2>/dev/null
iptables -t nat -F VLESS_PROXY 2>/dev/null; iptables -t nat -X VLESS_PROXY 2>/dev/null
ip6tables -t nat -D OUTPUT -p tcp -j VLESS_PROXY 2>/dev/null
ip6tables -t nat -F VLESS_PROXY 2>/dev/null; ip6tables -t nat -X VLESS_PROXY 2>/dev/null
EOFSCRIPT

    chmod +x "$CFG"/*.sh
}


#═══════════════════════════════════════════════════════════════════════════════
# 服务管理
#═══════════════════════════════════════════════════════════════════════════════
create_service() {
    local role=$(get_role) mode=$(get_mode) protocol=$(get_protocol)
    
    # 根据协议和角色确定启动命令
    local exec_cmd exec_name
    if [[ "$role" == "server" ]]; then
        case "$protocol" in
            vless|vless-xhttp|vless-ws|vless-vision|trojan)
                exec_cmd="/usr/local/bin/xray run -c $CFG/config.json"
                exec_name="xray"
                ;;
            socks|ss2022)
                exec_cmd="/usr/local/bin/xray run -c $CFG/config.json"
                exec_name="xray"
                ;;
            hy2)
                exec_cmd="/usr/local/bin/hysteria server -c $CFG/hy2.yaml"
                exec_name="hysteria"
                ;;
            snell)
                exec_cmd="/usr/local/bin/snell-server -c $CFG/snell.conf"
                exec_name="snell-server"
                ;;
            snell-v5)
                exec_cmd="/usr/local/bin/snell-server-v5 -c $CFG/snell-v5.conf"
                exec_name="snell-server-v5"
                ;;
            tuic)
                exec_cmd="/usr/local/bin/tuic-server -c $CFG/tuic.json"
                exec_name="tuic-server"
                ;;
            anytls)
                source "$CFG/anytls.info" 2>/dev/null
                exec_cmd="/usr/local/bin/anytls-server -l 0.0.0.0:$port -p $password"
                exec_name="anytls-server"
                ;;
        esac
    else
        # 客户端
        case "$protocol" in
            vless|vless-xhttp|vless-ws|vless-vision|trojan)
                exec_cmd="/usr/local/bin/xray run -c $CFG/config.json"
                exec_name="xray"
                ;;
            socks|ss2022)
                exec_cmd="/usr/local/bin/xray run -c $CFG/config.json"
                exec_name="xray"
                ;;
            hy2)
                exec_cmd="/usr/local/bin/hysteria client -c $CFG/hy2.yaml"
                exec_name="hysteria"
                ;;
            snell)
                # Snell 客户端需要 Surge/Clash，这里只是占位
                exec_cmd="echo 'Snell client requires Surge/Clash'"
                exec_name="snell-client"
                ;;
            snell-v5)
                # Snell v5 客户端需要 Surge/Clash，这里只是占位
                exec_cmd="echo 'Snell v5 client requires Surge/Clash'"
                exec_name="snell-v5-client"
                ;;
            tuic)
                exec_cmd="/usr/local/bin/tuic-client -c $CFG/config.json"
                exec_name="tuic-client"
                ;;
            anytls)
                source "$CFG/anytls.info" 2>/dev/null
                exec_cmd="/usr/local/bin/anytls-client -l 127.0.0.1:$SOCKS_PORT -s $server_ip:$port -p $password"
                exec_name="anytls-client"
                ;;
        esac
    fi
    
    # 对于 Xray 协议，使用统一的服务名；对于独立协议，使用独立服务名
    local service_name
    if echo "$XRAY_PROTOCOLS" | grep -q "$protocol"; then
        service_name="vless-reality"
    else
        service_name="vless-${protocol}"
    fi
    
    if [[ "$DISTRO" == "alpine" ]]; then
        cat > /etc/init.d/${service_name} << EOF
#!/sbin/openrc-run
name="Proxy Server ($protocol)"
command="${exec_cmd%% *}"
command_args="${exec_cmd#* }"
command_background="yes"
pidfile="/run/${service_name}.pid"
depend() { need net; }
EOF
        chmod +x /etc/init.d/${service_name}

        if [[ "$role" == "client" ]]; then
            if [[ "$mode" == "tun" ]]; then
                cat > /etc/init.d/vless-tun << EOF
#!/sbin/openrc-run
name="VLESS TUN"
command="/usr/local/bin/tun2socks"
command_args="-device tun0 -proxy socks5://127.0.0.1:10808 -loglevel silent"
command_background="yes"
pidfile="/run/vless-tun.pid"
depend() { need ${service_name}; }
start_pre() { /etc/vless-reality/tun-up.sh; }
stop_post() { /etc/vless-reality/tun-down.sh; }
EOF
                chmod +x /etc/init.d/vless-tun
            fi
        fi
    else
        cat > /etc/systemd/system/${service_name}.service << EOF
[Unit]
Description=Proxy Server ($protocol)
After=network.target

[Service]
Type=simple
ExecStart=$exec_cmd
Restart=always
RestartSec=3
LimitNOFILE=51200
[Install]
WantedBy=multi-user.target
EOF
        if [[ "$role" == "client" ]]; then
            cat > /etc/systemd/system/vless-watchdog.service << EOF
[Unit]
Description=Proxy Connection Watchdog
After=${service_name}.service
[Service]
Type=simple
ExecStart=$CFG/watchdog.sh
Restart=always
[Install]
WantedBy=multi-user.target
EOF
            if [[ "$mode" == "tun" ]]; then
                cat > /etc/systemd/system/vless-tun.service << EOF
[Unit]
Description=Proxy TUN
After=${service_name}.service
Requires=${service_name}.service
[Service]
Type=simple
ExecStartPre=$CFG/tun-up.sh
ExecStart=/usr/local/bin/tun2socks -device tun0 -proxy socks5://127.0.0.1:$SOCKS_PORT -loglevel silent
ExecStopPost=$CFG/tun-down.sh
Restart=always
RestartSec=5
LimitNOFILE=51200
[Install]
WantedBy=multi-user.target
EOF
            elif [[ "$mode" == "global" ]]; then
                cat > /etc/systemd/system/vless-global.service << EOF
[Unit]
Description=Proxy Global
After=${service_name}.service
Requires=${service_name}.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$CFG/global-up.sh
ExecStop=$CFG/global-down.sh
[Install]
WantedBy=multi-user.target
EOF
            fi
        fi
        systemctl daemon-reload
    fi
}

svc() {
    local action="$1" name="$2"
    if [[ "$DISTRO" == "alpine" ]]; then
        case "$action" in
            start)   
                if ! rc-service "$name" start 2>/tmp/svc_error.log; then
                    [[ -s /tmp/svc_error.log ]] && { _err "服务启动失败:"; cat /tmp/svc_error.log; }
                    rm -f /tmp/svc_error.log
                    return 1
                fi
                ;;
            stop)    rc-service "$name" stop &>/dev/null ;;
            enable)  rc-update add "$name" default &>/dev/null ;;
            restart) 
                if ! rc-service "$name" restart 2>/tmp/svc_error.log; then
                    [[ -s /tmp/svc_error.log ]] && { _err "服务重启失败:"; cat /tmp/svc_error.log; }
                    rm -f /tmp/svc_error.log
                    return 1
                fi
                ;;
            status)  rc-service "$name" status &>/dev/null ;;
        esac
    else
        case "$action" in
            start)   
                if ! systemctl start "$name" 2>/tmp/svc_error.log; then
                    [[ -s /tmp/svc_error.log ]] && { _err "服务启动失败:"; cat /tmp/svc_error.log; }
                    # 额外显示 systemctl status 信息
                    _err "详细状态信息:"
                    systemctl status "$name" --no-pager -l || true
                    rm -f /tmp/svc_error.log
                    return 1
                fi
                ;;
            stop)    systemctl stop "$name" &>/dev/null ;;
            enable)  systemctl enable "$name" &>/dev/null ;;
            restart) 
                if ! systemctl restart "$name" 2>/tmp/svc_error.log; then
                    [[ -s /tmp/svc_error.log ]] && { _err "服务重启失败:"; cat /tmp/svc_error.log; }
                    _err "详细状态信息:"
                    systemctl status "$name" --no-pager -l || true
                    rm -f /tmp/svc_error.log
                    return 1
                fi
                ;;
            status)  
                # active 或 activating 都算运行中
                local state=$(systemctl is-active "$name" 2>/dev/null)
                [[ "$state" == "active" || "$state" == "activating" ]]
                ;;
        esac
    fi
}

start_services() {
    local role=$(get_role) mode=$(get_mode)
    rm -f "$CFG/paused"
    
    if [[ "$role" == "server" ]]; then
        # 服务端：启动所有已注册的协议服务
        
        # 启动 Xray 服务（如果有 Xray 协议）
        local xray_protocols=$(get_xray_protocols)
        if [[ -n "$xray_protocols" ]]; then
            # 重新生成 Xray 配置（合并所有 Xray 协议）
            generate_xray_config
            
            # 验证配置文件
            if [[ -f "$CFG/config.json" ]]; then
                if ! jq empty "$CFG/config.json" 2>/dev/null; then
                    _err "Xray 配置文件 JSON 格式错误"
                    return 1
                fi
                _ok "Xray 配置文件检查通过"
            fi
            
            svc enable vless-reality
            if ! svc start vless-reality; then
                _err "Xray 服务启动失败，请检查上述错误信息"
                return 1
            fi
            # 将多行协议列表转换为单行，用空格分隔
            local xray_list=$(echo $xray_protocols | tr '\n' ' ')
            _ok "Xray 服务已启动 (协议: $xray_list)"
            sleep 1
        fi
        
        # 启动独立协议服务
        local independent_protocols=$(get_independent_protocols)
        local ind_proto
        for ind_proto in $independent_protocols; do
            local service_name="vless-${ind_proto}"
            svc enable "$service_name"
            if ! svc start "$service_name"; then
                _err "$ind_proto 服务启动失败"
                return 1
            fi
            _ok "$ind_proto 服务已启动"
            sleep 1
        done
    else
        # 客户端：根据协议类型启动对应服务
        local protocol=$(cat "$CFG/protocol" 2>/dev/null)
        local service_name
        
        if echo "$XRAY_PROTOCOLS" | grep -qw "$protocol"; then
            service_name="vless-reality"
        else
            service_name="vless-${protocol}"
        fi
        
        svc enable "$service_name"
        if ! svc start "$service_name"; then
            _err "$protocol 服务启动失败"
            # 显示详细错误信息
            _err "详细状态信息:"
            systemctl status "$service_name" --no-pager 2>/dev/null || true
            return 1
        fi
        _ok "$protocol 服务已启动"
        
        # 客户端额外服务
        if [[ "$DISTRO" != "alpine" ]]; then
            svc enable vless-watchdog
            svc start vless-watchdog
        fi

        case "$mode" in
            tun)
                [[ ! -x "/usr/local/bin/tun2socks" ]] && { _err "tun2socks 未安装"; return 1; }
                svc enable vless-tun
                svc start vless-tun || { _err "TUN 启动失败"; return 1; }
                ;;
            global)
                svc enable vless-global
                svc start vless-global || { _err "全局代理启动失败"; return 1; }
                ;;
            socks)
                echo ""
                _line
                _ok "SOCKS5代理已启动"
                _line
                ;;
        esac
    fi
    
    return 0
}

stop_services() {
    svc stop vless-watchdog 2>/dev/null
    svc stop vless-tun 2>/dev/null
    svc stop vless-global 2>/dev/null
    svc stop vless-reality 2>/dev/null
    # 停止所有独立协议服务
    for proto in $INDEPENDENT_PROTOCOLS; do
        svc stop "vless-${proto}" 2>/dev/null
    done
    ip link del tun0 &>/dev/null || true
}

create_shortcut() {
    local system_dir="/usr/local/bin"
    local system_script="$system_dir/vless.sh"
    local system_link="$system_dir/vless"
    local first_install=false
    local script_updated=false

    # 检查是否首次安装
    [[ ! -L "$system_link" && ! -f "$system_link" ]] && first_install=true

    # 获取当前脚本路径
    local current_script="$0"
    local real_path=""
    
    # DEBUG: 显示检测到的路径
    # echo "[DEBUG] \$0 = $current_script"
    # echo "[DEBUG] pwd = $(pwd)"
    
    # 排除流式运行 (curl | bash)
    if [[ "$current_script" == "bash" || "$current_script" == "-bash" || "$current_script" == "/bin/bash" || "$current_script" == "sh" || "$current_script" == "-" ]]; then
        # 流式运行，跳过迁移
        return 0
    fi
    
    # 获取绝对路径
    if [[ "$current_script" == /* ]]; then
        real_path="$current_script"
    else
        real_path="$(cd "$(dirname "$current_script")" && pwd)/$(basename "$current_script")"
    fi
    
    # echo "[DEBUG] real_path = $real_path"
    
    # 检查文件是否存在
    if [[ ! -f "$real_path" ]]; then
        # echo "[DEBUG] 文件不存在: $real_path"
        return 0
    fi

    # 迁移脚本到系统目录
    if [[ "$real_path" != "$system_script" ]]; then
        mkdir -p "$system_dir"
        if cp -f "$real_path" "$system_script"; then
            chmod +x "$system_script"
            script_updated=true
            # 删除原始脚本
            rm -f "$real_path" 2>/dev/null
        else
            _warn "复制脚本失败: $real_path -> $system_script"
            return 1
        fi
    fi

    # 创建软链接
    if [[ -f "$system_script" ]]; then
        rm -f "$system_link" /usr/bin/vless 2>/dev/null
        ln -sf "$system_script" "$system_link"
        ln -sf "$system_script" /usr/bin/vless
        hash -r 2>/dev/null
    fi

    # 提示 - 只要发生了迁移就提示
    if [[ "$script_updated" == "true" ]]; then
        echo ""
        _ok "快捷命令已创建: vless"
        echo ""
    fi
}

remove_shortcut() { 
    rm -f /usr/local/bin/vless /usr/local/bin/vless.sh /usr/bin/vless 2>/dev/null
    _ok "快捷命令已移除"
}

#═══════════════════════════════════════════════════════════════════════════════
# 节点管理
#═══════════════════════════════════════════════════════════════════════════════
# 保存节点 (支持所有协议)
# 参数: name protocol [协议特定参数...]
save_node() {
    mkdir -p "$CFG/nodes"
    local name="$1" protocol="$2"
    shift 2
    
    case "$protocol" in
        vless)
            # 参数: ip port uuid pubkey sid sni
            cat > "$CFG/nodes/$name" << EOF
protocol=vless
server_ip=$1
port=$2
uuid=$3
public_key=$4
short_id=$5
sni=$6
EOF
            ;;
        vless-xhttp)
            # 参数: ip port uuid pubkey sid sni path
            cat > "$CFG/nodes/$name" << EOF
protocol=vless-xhttp
server_ip=$1
port=$2
uuid=$3
public_key=$4
short_id=$5
sni=$6
path=$7
EOF
            ;;
        vless-vision)
            # 参数: ip port uuid sni
            cat > "$CFG/nodes/$name" << EOF
protocol=vless-vision
server_ip=$1
port=$2
uuid=$3
sni=$4
EOF
            ;;
        vless-ws)
            # 参数: ip port uuid sni path
            cat > "$CFG/nodes/$name" << EOF
protocol=vless-ws
server_ip=$1
port=$2
uuid=$3
sni=$4
path=$5
EOF
            ;;
        ss2022)
            # 参数: ip port method password
            cat > "$CFG/nodes/$name" << EOF
protocol=ss2022
server_ip=$1
port=$2
method=$3
password=$4
EOF
            ;;
        trojan)
            # 参数: ip port password sni
            cat > "$CFG/nodes/$name" << EOF
protocol=trojan
server_ip=$1
port=$2
password=$3
sni=$4
EOF
            ;;
        hy2)
            # 参数: ip port password sni
            cat > "$CFG/nodes/$name" << EOF
protocol=hy2
server_ip=$1
port=$2
password=$3
sni=$4
EOF
            ;;
        snell)
            # 参数: ip port psk version
            cat > "$CFG/nodes/$name" << EOF
protocol=snell
server_ip=$1
port=$2
psk=$3
version=$4
EOF
            ;;
        tuic)
            # 参数: ip port uuid password sni [cert_path]
            cat > "$CFG/nodes/$name" << EOF
protocol=tuic
server_ip=$1
port=$2
uuid=$3
password=$4
sni=$5
cert_path=${6:-/etc/vless-reality/certs/server.crt}
EOF
            ;;
    esac
}

list_nodes() {
    [[ ! -d "$CFG/nodes" ]] && return 1
    local current=$(cat "$CFG/current_node" 2>/dev/null) i=1
    for node in "$CFG/nodes"/*; do
        [[ ! -f "$node" ]] && continue
        source "$node"
        local name=$(basename "$node")
        local proto_type="${protocol:-vless}"
        local mark="" latency=$(test_latency "$server_ip" "$port" "$proto_type")
        [[ "$name" == "$current" ]] && mark=" ${G}[当前]${NC}"
        
        local color="${G}"
        [[ "$latency" == "超时" ]] && color="${R}"
        [[ "$latency" == "UDP" ]] && color="${C}"
        [[ "$latency" =~ ^([0-9]+)ms$ && ${BASH_REMATCH[1]} -gt 300 ]] && color="${Y}"
        
        # 显示协议类型
        local proto_short="$proto_type"
        case "$proto_short" in
            vless) proto_short="VLESS" ;;
            vless-xhttp) proto_short="VLESS-XHTTP" ;;
            vless-ws) proto_short="VLESS-WS" ;;
            ss2022) proto_short="SS2022" ;;
            hy2) proto_short="HY2" ;;
            trojan) proto_short="Trojan" ;;
            snell) proto_short="Snell" ;;
            tuic) proto_short="TUIC" ;;
        esac
        
        printf "  ${G}%2d${NC}) %-20s ${D}[%s]${NC} ${D}(%s:%s)${NC} ${color}%s${NC}%b\n" "$i" "$name" "$proto_short" "$server_ip" "$port" "$latency" "$mark"
        ((i++))
    done
    [[ $i -eq 1 ]] && return 1
    return 0
}

switch_node() {
    local node_file="$1"
    [[ ! -f "$node_file" ]] && return 1
    source "$node_file"
    
    _info "切换到节点: $(basename "$node_file")"
    stop_services
    
    # 根据协议调用不同的配置生成
    case "$protocol" in
        vless)
            gen_client_config "vless" "$server_ip" "$port" "$uuid" "$public_key" "$short_id" "$sni"
            ;;
        vless-xhttp)
            gen_client_config "vless-xhttp" "$server_ip" "$port" "$uuid" "$public_key" "$short_id" "$sni" "$path"
            ;;
        vless-vision)
            gen_client_config "vless-vision" "$server_ip" "$port" "$uuid" "$sni"
            ;;
        vless-ws)
            gen_client_config "vless-ws" "$server_ip" "$port" "$uuid" "$sni" "$path"
            ;;
        ss2022)
            gen_client_config "ss2022" "$server_ip" "$port" "$method" "$password"
            ;;
        trojan)
            gen_client_config "trojan" "$server_ip" "$port" "$password" "$sni"
            ;;
        hy2)
            gen_client_config "hy2" "$server_ip" "$port" "$password" "$sni"
            ;;
        snell)
            gen_client_config "snell" "$server_ip" "$port" "$psk" "$version"
            ;;
        tuic)
            gen_client_config "tuic" "$server_ip" "$port" "$uuid" "$password" "$sni" "$cert_path"
            ;;
        *)
            # 兼容旧格式节点 (默认vless)
            gen_client_config "vless" "$server_ip" "$port" "$uuid" "$public_key" "$short_id" "$sni"
            ;;
    esac
    
    echo "$(basename "$node_file")" > "$CFG/current_node"
    start_services && _ok "节点切换完成"
}

select_node() {
    local prompt="$1"
    SELECTED_NODE=""
    if ! list_nodes; then
        _warn "没有保存的节点"
        return 1
    fi
    _line
    echo ""
    local max=$(ls "$CFG/nodes" 2>/dev/null | wc -l)
    read -rp "  $prompt [1-$max]: " choice
    [[ ! "$choice" =~ ^[0-9]+$ ]] && { _err "无效选择"; return 1; }
    local file=$(ls "$CFG/nodes" 2>/dev/null | sed -n "${choice}p")
    [[ -z "$file" ]] && { _err "节点不存在"; return 1; }
    SELECTED_NODE="$CFG/nodes/$file"
    return 0
}

#═══════════════════════════════════════════════════════════════════════════════
# BBR 网络优化
#═══════════════════════════════════════════════════════════════════════════════

# 检查 BBR 状态
check_bbr_status() {
    local cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    local qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    [[ "$cc" == "bbr" && "$qdisc" == "fq" ]]
}

# 一键开启 BBR 优化
enable_bbr() {
    _header
    echo -e "  ${W}BBR 网络优化${NC}"
    _line
    
    # 检查内核版本
    local kernel_ver=$(uname -r | cut -d'-' -f1)
    local kernel_major=$(echo "$kernel_ver" | cut -d'.' -f1)
    local kernel_minor=$(echo "$kernel_ver" | cut -d'.' -f2)
    
    if [[ $kernel_major -lt 4 ]] || [[ $kernel_major -eq 4 && $kernel_minor -lt 9 ]]; then
        _err "内核版本 $(uname -r) 不支持 BBR (需要 4.9+)"
        return 1
    fi
    
    echo -e "  内核版本: ${G}$(uname -r)${NC} ✓"
    
    # 检查当前状态
    local current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    local current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    
    echo -e "  当前拥塞控制: ${Y}$current_cc${NC}"
    echo -e "  当前队列调度: ${Y}$current_qdisc${NC}"
    
    if check_bbr_status; then
        _line
        _ok "BBR 已启用，无需重复操作"
        return 0
    fi
    
    _line
    read -rp "  确认开启 BBR 优化? [Y/n]: " confirm
    [[ "$confirm" =~ ^[nN]$ ]] && return
    
    _info "加载 BBR 模块..."
    modprobe tcp_bbr 2>/dev/null || true
    
    # 检查 BBR 是否可用
    if ! sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q bbr; then
        _err "BBR 模块不可用，请检查内核配置"
        return 1
    fi
    
    # 获取系统内存大小
    local mem_mb=$(free -m | awk '/^Mem:/{print $2}')
    
    # 根据内存动态计算参数
    local rmem_max wmem_max tcp_rmem tcp_wmem somaxconn file_max
    if [[ $mem_mb -le 512 ]]; then
        rmem_max=8388608; wmem_max=8388608
        tcp_rmem="4096 65536 8388608"; tcp_wmem="4096 65536 8388608"
        somaxconn=32768; file_max=262144
    elif [[ $mem_mb -le 1024 ]]; then
        rmem_max=16777216; wmem_max=16777216
        tcp_rmem="4096 65536 16777216"; tcp_wmem="4096 65536 16777216"
        somaxconn=49152; file_max=524288
    elif [[ $mem_mb -le 2048 ]]; then
        rmem_max=33554432; wmem_max=33554432
        tcp_rmem="4096 87380 33554432"; tcp_wmem="4096 65536 33554432"
        somaxconn=65535; file_max=1048576
    else
        rmem_max=67108864; wmem_max=67108864
        tcp_rmem="4096 131072 67108864"; tcp_wmem="4096 87380 67108864"
        somaxconn=65535; file_max=2097152
    fi
    
    _info "写入优化配置..."
    
    local conf_file="/etc/sysctl.d/99-bbr-proxy.conf"
    cat > "$conf_file" << EOF
# BBR 网络优化配置 (由 vless 脚本生成)
# 生成时间: $(date)
# 内存: ${mem_mb}MB

# BBR 拥塞控制
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Socket 缓冲区
net.core.rmem_max = $rmem_max
net.core.wmem_max = $wmem_max
net.ipv4.tcp_rmem = $tcp_rmem
net.ipv4.tcp_wmem = $tcp_wmem

# 连接队列
net.core.somaxconn = $somaxconn
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_max_syn_backlog = $somaxconn

# TCP 优化
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 180000
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3

# 文件句柄
fs.file-max = $file_max

# 内存优化
vm.swappiness = 10
EOF
    
    _info "应用配置..."
    if sysctl --system >/dev/null 2>&1; then
        _ok "配置已生效"
    else
        _err "配置应用失败"
        return 1
    fi
    
    # 验证结果
    _line
    local new_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    local new_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    
    echo -e "  拥塞控制: ${G}$new_cc${NC}"
    echo -e "  队列调度: ${G}$new_qdisc${NC}"
    
    if [[ "$new_cc" == "bbr" && "$new_qdisc" == "fq" ]]; then
        _ok "BBR 优化已成功启用!"
    else
        _warn "BBR 可能未完全生效，请检查系统日志"
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 多协议管理菜单
#═══════════════════════════════════════════════════════════════════════════════

# 显示所有已安装协议的信息（带选择查看详情功能）
show_all_protocols_info() {
    local installed=$(get_installed_protocols)
    [[ -z "$installed" ]] && { _warn "未安装任何协议"; return; }
    
    while true; do
        _header
        echo -e "  ${W}已安装协议配置${NC}"
        _line
        
        local xray_protocols=$(get_xray_protocols)
        local independent_protocols=$(get_independent_protocols)
        local all_protocols=()
        local idx=1
        
        if [[ -n "$xray_protocols" ]]; then
            echo -e "  ${Y}Xray 协议 (共享服务):${NC}"
            for protocol in $xray_protocols; do
                local info_file="$CFG/${protocol}.info"
                if [[ -f "$info_file" ]]; then
                    source "$info_file"
                    echo -e "    ${G}$idx${NC}) $(get_protocol_name $protocol) - 端口: ${G}$port${NC}"
                    all_protocols+=("$protocol")
                    ((idx++))
                fi
            done
            echo ""
        fi
        
        if [[ -n "$independent_protocols" ]]; then
            echo -e "  ${Y}独立协议 (独立服务):${NC}"
            for protocol in $independent_protocols; do
                local info_file="$CFG/${protocol}.info"
                if [[ -f "$info_file" ]]; then
                    source "$info_file"
                    echo -e "    ${G}$idx${NC}) $(get_protocol_name $protocol) - 端口: ${G}$port${NC}"
                    all_protocols+=("$protocol")
                    ((idx++))
                fi
            done
            echo ""
        fi
        
        _line
        echo -e "  ${D}输入序号查看详细配置/链接/二维码${NC}"
        _item "0" "返回主菜单"
        _line
        
        read -rp "  请选择 [0-$((idx-1))]: " choice
        
        if [[ "$choice" == "0" ]]; then
            return
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -lt $idx ]]; then
            local selected_protocol="${all_protocols[$((choice-1))]}"
            show_single_protocol_info "$selected_protocol"
        else
            _err "无效选择"
            sleep 1
        fi
    done
}

# 显示单个协议的详细配置信息（包含链接和二维码）
# 参数: $1=协议名, $2=是否清屏(可选，默认true)
show_single_protocol_info() {
    local protocol="$1"
    local clear_screen="${2:-true}"
    local info_file="$CFG/${protocol}.info"
    [[ ! -f "$info_file" ]] && { _err "协议配置不存在: $info_file"; return; }
    
    # 清除可能残留的变量，避免显示错误的配置
    local uuid="" port="" sni="" short_id="" public_key="" private_key="" path=""
    local password="" username="" method="" psk="" version=""
    local ipv4="" ipv6="" server_ip=""
    
    # 从 info 文件读取配置
    source "$info_file"
    
    # 重新获取 IP（info 文件中的可能是旧的）
    [[ -z "$ipv4" ]] && ipv4=$(get_ipv4)
    [[ -z "$ipv6" ]] && ipv6=$(get_ipv6)
    
    [[ "$clear_screen" == "true" ]] && _header
    _line
    echo -e "  ${W}$(get_protocol_name $protocol) 配置详情${NC}"
    _line
    
    [[ -n "$ipv4" ]] && echo -e "  IPv4: ${G}$ipv4${NC}"
    [[ -n "$ipv6" ]] && echo -e "  IPv6: ${G}$ipv6${NC}"
    echo -e "  端口: ${G}$port${NC}"
    
    case "$protocol" in
        vless)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  公钥: ${G}$public_key${NC}"
            echo -e "  SNI: ${G}$sni${NC}  ShortID: ${G}$short_id${NC}"
            ;;
        vless-xhttp)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  公钥: ${G}$public_key${NC}"
            echo -e "  SNI: ${G}$sni${NC}  ShortID: ${G}$short_id${NC}"
            echo -e "  Path: ${G}$path${NC}"
            ;;
        vless-vision|vless-ws)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            [[ -n "$path" ]] && echo -e "  Path: ${G}$path${NC}"
            ;;
        ss2022)
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  加密: ${G}$method${NC}"
            ;;
        hy2|trojan|anytls)
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            ;;
        snell|snell-v5)
            echo -e "  PSK: ${G}$psk${NC}"
            echo -e "  版本: ${G}v$version${NC}"
            ;;
        tuic)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            ;;
        socks)
            echo -e "  用户名: ${G}$username${NC}"
            echo -e "  密码: ${G}$password${NC}"
            ;;
    esac
    
    _line
    
    # 生成并显示分享链接和二维码
    for ver in v4 v6; do
        local ip_addr
        [[ "$ver" == "v4" ]] && ip_addr="$ipv4" || ip_addr="$ipv6"
        [[ -z "$ip_addr" ]] && continue
        
        # IPv6 需要加方括号
        [[ "$ver" == "v6" ]] && ip_addr="[$ip_addr]"
        
        local link join_code
        case "$protocol" in
            vless)
                link=$(gen_vless_link "$ip_addr" "$port" "$uuid" "$public_key" "$short_id" "$sni")
                join_code=$(echo "REALITY|${ip_addr}|${port}|${uuid}|${public_key}|${short_id}|${sni}" | base64 -w 0)
                ;;
            vless-xhttp)
                link=$(gen_vless_xhttp_link "$ip_addr" "$port" "$uuid" "$public_key" "$short_id" "$sni" "$path")
                join_code=$(echo "REALITY-XHTTP|${ip_addr}|${port}|${uuid}|${public_key}|${short_id}|${sni}|${path}" | base64 -w 0)
                ;;
            vless-vision)
                link=$(gen_vless_vision_link "$ip_addr" "$port" "$uuid" "$sni")
                join_code=$(echo "VLESS-VISION|${ip_addr}|${port}|${uuid}|${sni}" | base64 -w 0)
                ;;
            vless-ws)
                link=$(gen_vless_ws_link "$ip_addr" "$port" "$uuid" "$sni" "$path")
                join_code=$(echo "VLESS-WS|${ip_addr}|${port}|${uuid}|${sni}|${path}" | base64 -w 0)
                ;;
            ss2022)
                link=$(gen_ss2022_link "$ip_addr" "$port" "$method" "$password")
                join_code=$(echo "SS2022|${ip_addr}|${port}|${method}|${password}" | base64 -w 0)
                ;;
            hy2)
                link=$(gen_hy2_link "$ip_addr" "$port" "$password" "$sni")
                join_code=$(echo "HY2|${ip_addr}|${port}|${password}|${sni}" | base64 -w 0)
                ;;
            trojan)
                link=$(gen_trojan_link "$ip_addr" "$port" "$password" "$sni")
                join_code=$(echo "TROJAN|${ip_addr}|${port}|${password}|${sni}" | base64 -w 0)
                ;;
            snell)
                link=$(gen_snell_link "$ip_addr" "$port" "$psk" "$version")
                join_code=$(echo "SNELL|${ip_addr}|${port}|${psk}|${version}" | base64 -w 0)
                ;;
            snell-v5)
                link=$(gen_snell_v5_link "$ip_addr" "$port" "$psk" "$version")
                join_code=$(echo "SNELL-V5|${ip_addr}|${port}|${psk}|${version}" | base64 -w 0)
                ;;
            tuic)
                link=$(gen_tuic_link "$ip_addr" "$port" "$uuid" "$password" "$sni")
                join_code=$(echo "TUIC|${ip_addr}|${port}|${uuid}|${password}|${sni}" | base64 -w 0)
                ;;
            anytls)
                link=$(gen_anytls_link "$ip_addr" "$port" "$password" "$sni")
                join_code=$(echo "ANYTLS|${ip_addr}|${port}|${password}|${sni}" | base64 -w 0)
                ;;
            socks)
                link=$(gen_socks_link "$ip_addr" "$port" "$username" "$password")
                join_code=$(echo "SOCKS|${ip_addr}|${port}|${username}|${password}" | base64 -w 0)
                ;;
        esac
        
        echo ""
        echo -e "  ${Y}═══ IP${ver^^} 连接信息 ═══${NC}"
        echo -e "  ${C}JOIN码:${NC}"
        echo -e "  ${G}$join_code${NC}"
        echo ""
        
        if [[ "$protocol" == "socks" ]]; then
            # SOCKS5 显示两种链接格式
            local socks_link="socks5://${username}:${password}@${ip_addr}:${port}#SOCKS5-${ip_addr}"
            echo -e "  ${C}SOCKS5 链接:${NC}"
            echo -e "  ${G}$socks_link${NC}"
            echo ""
            echo -e "  ${C}Telegram 代理链接:${NC}"
            echo -e "  ${G}$link${NC}"
            echo ""
            echo -e "  ${C}二维码 (SOCKS5):${NC}"
            echo -e "  ${G}$(gen_qr "$socks_link")${NC}"
        else
            echo -e "  ${C}分享链接:${NC}"
            echo -e "  ${G}$link${NC}"
            echo ""
            echo -e "  ${C}二维码:${NC}"
            echo -e "  ${G}$(gen_qr "$link")${NC}"
        fi
    done
    
    _line
    [[ "$clear_screen" == "true" ]] && _pause
}

# 管理协议服务
manage_protocol_services() {
    local installed=$(get_installed_protocols)
    [[ -z "$installed" ]] && { _warn "未安装任何协议"; return; }
    
    while true; do
        _header
        echo -e "  ${W}协议服务管理${NC}"
        _line
        show_protocols_overview  # 使用简洁概览
        
        _item "1" "重启所有服务"
        _item "2" "停止所有服务"
        _item "3" "启动所有服务"
        _item "4" "查看服务状态"
        _item "0" "返回主菜单"
        _line
        
        read -rp "  请选择: " choice
        case $choice in
            1) 
                _info "重启所有服务..."
                stop_services; sleep 2; start_services && _ok "所有服务已重启"
                ;;
            2) 
                _info "停止所有服务..."
                stop_services; touch "$CFG/paused"; _ok "所有服务已停止"
                ;;
            3) 
                _info "启动所有服务..."
                start_services && _ok "所有服务已启动"
                ;;
            4) show_services_status ;;
            0) return ;;
            *) _err "无效选择" ;;
        esac
        _pause
    done
}

# 简洁的协议概览（用于服务管理页面）
show_protocols_overview() {
    local xray_protocols=$(get_xray_protocols)
    local independent_protocols=$(get_independent_protocols)
    
    echo -e "  ${C}已安装协议概览${NC}"
    _line
    
    if [[ -n "$xray_protocols" ]]; then
        echo -e "  ${Y}Xray 协议 (共享服务):${NC}"
        for protocol in $xray_protocols; do
            local info_file="$CFG/${protocol}.info"
            if [[ -f "$info_file" ]]; then
                source "$info_file"
                echo -e "    ${G}●${NC} $(get_protocol_name $protocol) - 端口: ${G}$port${NC}"
            fi
        done
        echo ""
    fi
    
    if [[ -n "$independent_protocols" ]]; then
        echo -e "  ${Y}独立协议 (独立服务):${NC}"
        for protocol in $independent_protocols; do
            local info_file="$CFG/${protocol}.info"
            if [[ -f "$info_file" ]]; then
                source "$info_file"
                echo -e "    ${G}●${NC} $(get_protocol_name $protocol) - 端口: ${G}$port${NC}"
            fi
        done
        echo ""
    fi
    _line
}

# 显示服务状态
show_services_status() {
    _line
    echo -e "  ${C}服务状态${NC}"
    _line
    
    # Xray 服务状态
    local xray_protocols=$(get_xray_protocols)
    if [[ -n "$xray_protocols" ]]; then
        if svc status vless-reality; then
            echo -e "  ${G}●${NC} Xray 服务 - ${G}运行中${NC}"
            # 显示各协议
            for proto in $xray_protocols; do
                echo -e "      ${D}└${NC} $(get_protocol_name $proto)"
            done
        else
            echo -e "  ${R}●${NC} Xray 服务 - ${R}已停止${NC}"
        fi
    fi
    
    # 独立协议服务状态
    local independent_protocols=$(get_independent_protocols)
    for protocol in $independent_protocols; do
        local service_name
        case "$protocol" in
            hy2) service_name="vless-hy2" ;;
            tuic) service_name="vless-tuic" ;;
            snell) service_name="vless-snell" ;;
            snell-v5) service_name="vless-snell-v5" ;;
            anytls) service_name="vless-anytls" ;;
            *) service_name="vless-${protocol}" ;;
        esac
        
        local proto_name=$(get_protocol_name $protocol)
        if svc status "$service_name"; then
            echo -e "  ${G}●${NC} $proto_name - ${G}运行中${NC}"
        else
            echo -e "  ${R}●${NC} $proto_name - ${R}已停止${NC}"
        fi
    done
    _line
}

# 卸载指定协议
uninstall_specific_protocol() {
    local installed=$(get_installed_protocols)
    [[ -z "$installed" ]] && { _warn "未安装任何协议"; return; }
    
    _header
    echo -e "  ${W}卸载指定协议${NC}"
    _line
    
    echo -e "  ${Y}已安装的协议:${NC}"
    local i=1
    for protocol in $installed; do
        echo -e "    ${G}$i${NC}) $(get_protocol_name $protocol)"
        ((i++))
    done
    echo ""
    
    read -rp "  选择要卸载的协议 [1-$((i-1))]: " choice
    [[ ! "$choice" =~ ^[0-9]+$ ]] && { _err "无效选择"; return; }
    
    local selected_protocol=$(echo "$installed" | sed -n "${choice}p")
    [[ -z "$selected_protocol" ]] && { _err "协议不存在"; return; }
    
    echo -e "  将卸载: ${R}$(get_protocol_name $selected_protocol)${NC}"
    read -rp "  确认卸载? [y/N]: " confirm
    [[ ! "$confirm" =~ ^[yY]$ ]] && return
    
    _info "卸载 $selected_protocol..."
    
    # 停止相关服务
    if echo "$XRAY_PROTOCOLS" | grep -q "$selected_protocol"; then
        # Xray 协议：需要重新生成配置
        unregister_protocol "$selected_protocol"
        rm -f "$CFG/${selected_protocol}.info"
        
        # 如果还有其他 Xray 协议，重新生成配置
        local remaining_xray=$(get_xray_protocols)
        if [[ -n "$remaining_xray" ]]; then
            generate_xray_config
            svc restart vless-reality
        else
            svc stop vless-reality
        fi
    else
        # 独立协议：直接停止和删除服务
        local service_name="vless-${selected_protocol}"
        svc stop "$service_name"
        unregister_protocol "$selected_protocol"
        rm -f "$CFG/${selected_protocol}.info"
        
        # 删除服务文件
        if [[ "$DISTRO" == "alpine" ]]; then
            rm -f "/etc/init.d/$service_name"
        else
            rm -f "/etc/systemd/system/${service_name}.service"
            systemctl daemon-reload
        fi
    fi
    
    _ok "$selected_protocol 已卸载"
}

#═══════════════════════════════════════════════════════════════════════════════
# 菜单操作 (v3.2: 完整复原所有功能函数)
#═══════════════════════════════════════════════════════════════════════════════
show_server_info() {
    [[ "$(get_role)" != "server" ]] && return
    
    # 多协议模式：显示所有协议的配置
    local installed=$(get_installed_protocols)
    local protocol_count=$(echo "$installed" | wc -w)
    
    if [[ $protocol_count -eq 1 ]]; then
        # 单协议：直接显示详细信息
        show_single_protocol_info "$installed"
    else
        # 多协议：显示协议列表供选择
        show_all_protocols_info
    fi
}

show_client_info() {
    [[ ! -f "$CFG/info" ]] && { _err "未找到节点信息"; return 1; }
    source "$CFG/info"
    local current=$(cat "$CFG/current_node" 2>/dev/null || echo "默认节点")
    local proto=$(get_protocol)
    
    _line
    echo -e "  ${C}当前节点: ${G}$current${NC}"
    echo -e "  ${C}协议: ${G}$(get_protocol_name $proto)${NC}"
    _line
    echo -e "  服务器: ${G}$server_ip:$port${NC}"
    
    case "$proto" in
        vless)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            echo -e "  ShortID: ${G}$short_id${NC}"
            ;;
        vless-xhttp)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            echo -e "  ShortID: ${G}$short_id${NC}"
            echo -e "  Path: ${G}$path${NC}"
            ;;
        vless-ws)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            echo -e "  Path: ${G}$path${NC}"
            ;;
        ss2022)
            echo -e "  加密: ${G}$method${NC}"
            echo -e "  密码: ${G}$password${NC}"
            ;;
        trojan|hy2)
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            ;;
        snell)
            echo -e "  PSK: ${G}$psk${NC}"
            echo -e "  版本: ${G}v$version${NC}"
            ;;
        tuic)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            ;;
    esac
    _line
}

do_switch_mode() {
    [[ "$(get_role)" != "client" ]] && { _err "仅客户端支持"; return; }
    local current=$(get_mode)
    local protocol=$(get_protocol)
    
    # Snell 不支持模式切换
    if [[ "$protocol" == "snell" ]]; then
        _warn "Snell 协议仅支持 Surge/Clash 等客户端，不支持模式切换"
        return
    fi
    
    _header
    echo -e "  ${W}切换模式${NC}"
    echo -e "  当前: ${G}$(get_mode_name $current)${NC}"
    _line
    _item "1" "TUN 网卡"
    _item "2" "全局代理"
    _item "3" "SOCKS5代理"
    echo ""
    
    local new_mode
    while true; do
        read -rp "  选择 [1-3]: " choice
        case $choice in
            1) new_mode="tun"; break ;;
            2) new_mode="global"; break ;;
            3) new_mode="socks"; break ;;
            *) _err "无效选择" ;;
        esac
    done
    [[ "$new_mode" == "$current" ]] && { _warn "已是当前模式"; return; }
    
    _info "切换模式..."
    svc stop vless-tun 2>/dev/null
    svc stop vless-global 2>/dev/null
    
    echo "$new_mode" > "$CFG/mode"
    source "$CFG/info"
    
    # 根据协议重新生成配置
    case "$protocol" in
        vless)
            gen_client_config "vless" "$server_ip" "$port" "$uuid" "$public_key" "$short_id" "$sni"
            ;;
        vless-xhttp)
            gen_client_config "vless-xhttp" "$server_ip" "$port" "$uuid" "$public_key" "$short_id" "$sni" "$path"
            ;;
        vless-vision)
            gen_client_config "vless-vision" "$server_ip" "$port" "$uuid" "$sni"
            ;;
        vless-ws)
            gen_client_config "vless-ws" "$server_ip" "$port" "$uuid" "$sni" "$path"
            ;;
        ss2022)
            gen_client_config "ss2022" "$server_ip" "$port" "$method" "$password"
            ;;
        trojan)
            gen_client_config "trojan" "$server_ip" "$port" "$password" "$sni"
            ;;
        hy2)
            gen_client_config "hy2" "$server_ip" "$port" "$password" "$sni"
            ;;
        tuic)
            gen_client_config "tuic" "$server_ip" "$port" "$uuid" "$password" "$sni"
            ;;
    esac
    
    create_scripts
    create_service
    svc restart vless-reality
    sleep 1
    
    case "$new_mode" in
        tun)
            [[ ! -x "/usr/local/bin/tun2socks" ]] && { _err "tun2socks 未安装"; return 1; }
            svc enable vless-tun; svc start vless-tun || { _err "TUN 启动失败"; return 1; }
            ;;
        global)
            svc enable vless-global; svc start vless-global || { _err "全局代理启动失败"; return 1; }
            ;;
        socks)
            echo -e "  SOCKS5代理: ${G}socks5://127.0.0.1:$SOCKS_PORT${NC}"
            ;;
    esac
    
    _ok "模式切换完成"
    [[ "$new_mode" != "socks" ]] && { sleep 1; test_connection; }
}

do_add_node() {
    [[ "$(get_role)" != "client" ]] && { _err "仅客户端支持"; return; }
    
    _header
    echo -e "  ${W}添加新节点${NC}"
    _line
    read -rp "  JOIN 码: " join_code
    [[ -z "$join_code" ]] && { _err "JOIN 码不能为空"; return; }

    local decoded=$(echo "$join_code" | base64 -d 2>/dev/null)
    [[ -z "$decoded" ]] && { _err "无效的 JOIN 码"; return; }
    
    # 解析不同协议的JOIN码
    local protocol_type server_ip port
    local uuid pubkey sid sni path password method psk version
    
    if [[ "$decoded" =~ ^REALITY-XHTTP\| ]]; then
        # REALITY-XHTTP|ip|port|uuid|pubkey|sid|sni|path
        IFS='|' read -r _ server_ip port uuid pubkey sid sni path <<< "$decoded"
        protocol_type="vless-xhttp"
    elif [[ "$decoded" =~ ^REALITY\| ]]; then
        # REALITY|ip|port|uuid|pubkey|sid|sni
        IFS='|' read -r _ server_ip port uuid pubkey sid sni <<< "$decoded"
        protocol_type="vless"
    elif [[ "$decoded" =~ ^VLESS-VISION\| ]]; then
        # VLESS-VISION|ip|port|uuid|sni
        IFS='|' read -r _ server_ip port uuid sni <<< "$decoded"
        protocol_type="vless-vision"
    elif [[ "$decoded" =~ ^VLESS-WS\| ]]; then
        # VLESS-WS|ip|port|uuid|sni|path
        IFS='|' read -r _ server_ip port uuid sni path <<< "$decoded"
        protocol_type="vless-ws"
    elif [[ "$decoded" =~ ^SS2022\| ]]; then
        # SS2022|ip|port|method|password
        IFS='|' read -r _ server_ip port method password <<< "$decoded"
        protocol_type="ss2022"
    elif [[ "$decoded" =~ ^TROJAN\| ]]; then
        # TROJAN|ip|port|password|sni
        IFS='|' read -r _ server_ip port password sni <<< "$decoded"
        protocol_type="trojan"
    elif [[ "$decoded" =~ ^HY2\| ]]; then
        # HY2|ip|port|password|sni
        IFS='|' read -r _ server_ip port password sni <<< "$decoded"
        protocol_type="hy2"
    elif [[ "$decoded" =~ ^SNELL\| ]]; then
        # SNELL|ip|port|psk|version
        IFS='|' read -r _ server_ip port psk version <<< "$decoded"
        protocol_type="snell"
    elif [[ "$decoded" =~ ^TUIC\| ]]; then
        # TUIC|ip|port|uuid|password|sni
        IFS='|' read -r _ server_ip port uuid password sni <<< "$decoded"
        protocol_type="tuic"
    else
        _err "无效的 JOIN 码格式"; return
    fi
    
    [[ -z "$server_ip" || -z "$port" ]] && { _err "JOIN 码解析失败"; return; }
    
    echo -e "  服务器: ${G}$server_ip:$port${NC}"
    echo -e "  协议: ${G}$(get_protocol_name $protocol_type)${NC}"
    read -rp "  节点名称 (留空自动): " node_name
    [[ -z "$node_name" ]] && node_name="node_${server_ip}_${port}"
    
    # 根据协议保存节点
    case "$protocol_type" in
        vless)
            save_node "$node_name" "vless" "$server_ip" "$port" "$uuid" "$pubkey" "$sid" "$sni"
            ;;
        vless-xhttp)
            save_node "$node_name" "vless-xhttp" "$server_ip" "$port" "$uuid" "$pubkey" "$sid" "$sni" "$path"
            ;;
        vless-vision)
            save_node "$node_name" "vless-vision" "$server_ip" "$port" "$uuid" "$sni"
            ;;
        vless-ws)
            save_node "$node_name" "vless-ws" "$server_ip" "$port" "$uuid" "$sni" "$path"
            ;;
        ss2022)
            save_node "$node_name" "ss2022" "$server_ip" "$port" "$method" "$password"
            ;;
        trojan)
            save_node "$node_name" "trojan" "$server_ip" "$port" "$password" "$sni"
            ;;
        hy2)
            save_node "$node_name" "hy2" "$server_ip" "$port" "$password" "$sni"
            ;;
        snell)
            save_node "$node_name" "snell" "$server_ip" "$port" "$psk" "$version"
            ;;
        tuic)
            # TUIC 需要证书
            echo ""
            _warn "TUIC v5 要求客户端必须持有服务端证书"
            read -rp "  证书文件路径 (默认 /etc/vless-reality/certs/server.crt): " cert_input
            local cert_path="${cert_input:-/etc/vless-reality/certs/server.crt}"
            if [[ ! -f "$cert_path" ]]; then
                _warn "证书文件不存在，请确保稍后下载证书到: $cert_path"
            fi
            save_node "$node_name" "tuic" "$server_ip" "$port" "$uuid" "$password" "$sni" "$cert_path"
            ;;
    esac
    
    _ok "节点已添加: $node_name"
    
    read -rp "  立即切换? [Y/n]: " sw
    [[ ! "$sw" =~ ^[nN]$ ]] && { switch_node "$CFG/nodes/$node_name"; test_connection; }
}

do_switch_node() {
    [[ "$(get_role)" != "client" ]] && { _err "仅客户端支持"; return; }
    _header
    echo -e "  ${W}切换节点${NC}"
    _line
    
    select_node "选择节点" || return
    switch_node "$SELECTED_NODE"
    sleep 1; test_connection
}

do_delete_node() {
    [[ "$(get_role)" != "client" ]] && { _err "仅客户端支持"; return; }
    _header
    echo -e "  ${W}删除节点${NC}"
    _line
    
    select_node "选择要删除的节点" || return
    local node="$SELECTED_NODE"
    [[ -z "$node" ]] && return
    
    local name=$(basename "$node")
    local current=$(cat "$CFG/current_node" 2>/dev/null)
    [[ "$name" == "$current" ]] && { _err "不能删除当前节点"; return; }
    
    read -rp "  确认删除 $name? [y/N]: " confirm
    [[ "$confirm" =~ ^[yY]$ ]] && { rm -f "$node"; _ok "已删除: $name"; }
}

do_uninstall() {
    check_installed || { _warn "未安装"; return; }
    read -rp "  确认卸载? [y/N]: " confirm
    [[ ! "$confirm" =~ ^[yY]$ ]] && return
    
    # 记录当前运行的脚本路径（卸载后删除）
    local current_script="$0"
    local script_to_delete=""
    if [[ "$current_script" != "bash" && "$current_script" != "-bash" && "$current_script" != "/bin/bash" && "$current_script" != "sh" && "$current_script" != "-" ]]; then
        if [[ "$current_script" == /* ]]; then
            script_to_delete="$current_script"
        else
            script_to_delete="$(cd "$(dirname "$current_script")" && pwd)/$(basename "$current_script")"
        fi
    fi
    
    _info "停止所有服务..."
    stop_services
    
    # 强力清理残留进程
    force_cleanup
    
    _info "删除服务文件..."
    if [[ "$DISTRO" == "alpine" ]]; then
        # Alpine: 删除所有 vless 相关的 OpenRC 服务
        for svc_file in /etc/init.d/vless-*; do
            [[ -f "$svc_file" ]] && {
                local svc_name=$(basename "$svc_file")
                rc-update del "$svc_name" default 2>/dev/null
                rm -f "$svc_file"
            }
        done
    else
        # Debian/Ubuntu/CentOS: 删除所有 vless 相关的 systemd 服务
        systemctl stop vless-* 2>/dev/null
        systemctl disable vless-* 2>/dev/null
        rm -f /etc/systemd/system/vless-*.service
        systemctl daemon-reload
    fi
    
    _info "删除配置目录..."
    rm -rf "$CFG"
    
    _info "删除快捷命令和脚本..."
    rm -f /usr/local/bin/vless /usr/local/bin/vless.sh /usr/bin/vless 2>/dev/null
    
    # 删除当前目录的脚本（如果是从其他位置运行的）
    if [[ -n "$script_to_delete" && -f "$script_to_delete" ]]; then
        rm -f "$script_to_delete" 2>/dev/null
    fi
    
    _ok "卸载完成"
    _info "已保留的软件包: xray, hysteria, snell-server, tuic-server, anytls-server, tun2socks"
    _info "如需删除，请手动执行: rm -f /usr/local/bin/{xray,hysteria,snell-server*,tuic-*,anytls-*,tun2socks}"
}

#═══════════════════════════════════════════════════════════════════════════════
# 安装流程
#═══════════════════════════════════════════════════════════════════════════════

# 协议选择菜单
select_protocol() {
    echo ""
    _line
    echo -e "  ${W}选择代理协议${NC}"
    _line
    _item "1" "VLESS + Reality ${D}(推荐, 抗封锁)${NC}"
    _item "2" "VLESS + Reality + XHTTP ${D}(多路复用)${NC}"
    _item "3" "VLESS + WS + TLS ${D}(CDN友好)${NC}"
    _item "4" "VLESS-XTLS-Vision ${D}(Vision流控)${NC}"
    _item "5" "SOCKS5 ${D}(经典代理)${NC}"
    _item "6" "Shadowsocks 2022 ${D}(新版加密)${NC}"
    _item "7" "Hysteria2 ${D}(UDP加速, 高速)${NC}"
    _item "8" "Trojan ${D}(伪装HTTPS)${NC}"
    _item "9" "Snell v4 ${D}(Surge专用)${NC}"
    _item "10" "Snell v5 ${D}(Surge 5.0新版)${NC}"
    _item "11" "AnyTLS ${D}(多协议TLS代理)${NC}"
    _item "12" "TUIC v5 ${D}(QUIC协议)${NC}"
    echo ""
    
    while true; do
        read -rp "  选择协议 [1-12]: " choice
        case $choice in
            1) SELECTED_PROTOCOL="vless"; break ;;
            2) SELECTED_PROTOCOL="vless-xhttp"; break ;;
            3) SELECTED_PROTOCOL="vless-ws"; break ;;
            4) SELECTED_PROTOCOL="vless-vision"; break ;;
            5) SELECTED_PROTOCOL="socks"; break ;;
            6) SELECTED_PROTOCOL="ss2022"; break ;;
            7) SELECTED_PROTOCOL="hy2"; break ;;
            8) SELECTED_PROTOCOL="trojan"; break ;;
            9) SELECTED_PROTOCOL="snell"; break ;;
            10) SELECTED_PROTOCOL="snell-v5"; break ;;
            11) SELECTED_PROTOCOL="anytls"; break ;;
            12) SELECTED_PROTOCOL="tuic"; break ;;
            *) _err "无效选择" ;;
        esac
    done
}

do_install_server() {
    # === 删除单协议限制，改为多协议支持 ===
    # check_installed && { _warn "已安装，请先卸载"; return; }
    _header
    echo -e "  ${W}服务端安装向导${NC}"
    echo -e "  系统: ${C}$DISTRO${NC}"
    
    # 选择协议
    select_protocol
    local protocol="$SELECTED_PROTOCOL"
    
    # 检查该协议是否已安装
    if is_protocol_installed "$protocol"; then
        _warn "协议 $(get_protocol_name $protocol) 已安装"
        read -rp "  是否重新安装? [y/N]: " reinstall
        if [[ "$reinstall" =~ ^[yY]$ ]]; then
            _info "卸载现有 $protocol 协议..."
            unregister_protocol "$protocol"
            rm -f "$CFG/${protocol}.info"
        else
            return
        fi
    fi
    
    _info "清理环境..."
    force_cleanup
    sync_time

    _info "检测网络环境..."
    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    echo -e "  IPv4: ${ipv4:-${R}无${NC}}"
    echo -e "  IPv6: ${ipv6:-${R}无${NC}}"
    [[ -z "$ipv4" && -z "$ipv6" ]] && { _err "无法获取公网IP"; return 1; }
    echo ""

    install_deps || return
    
    # 根据协议安装对应软件
    case "$protocol" in
        vless|vless-xhttp|vless-ws|vless-vision|ss2022|trojan)
            install_xray || return
            ;;
        hy2)
            install_hysteria || return
            ;;
        snell)
            install_snell || return
            ;;
        snell-v5)
            install_snell_v5 || return
            ;;
        tuic)
            install_tuic "server" || return
            ;;
        anytls)
            install_anytls || return
            ;;
    esac

    _info "生成配置参数..."
    local port=$(gen_port)
    
    case "$protocol" in
        vless)
            local uuid=$(gen_uuid) sid=$(gen_sid) sni=$(gen_sni)
            local keys=$(xray x25519 2>/dev/null)
            [[ -z "$keys" ]] && { _err "密钥生成失败"; return 1; }
            local privkey=$(echo "$keys" | grep -iE "(PrivateKey|Private key)" | awk '{print $NF}')
            local pubkey=$(echo "$keys" | grep -iE "(Password|Public key)" | awk '{print $NF}')
            [[ -z "$privkey" || -z "$pubkey" ]] && { _err "密钥提取失败"; return 1; }
            
            echo ""
            _line
            echo -e "  ${C}VLESS+Reality 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}  UUID: ${G}${uuid:0:8}...${NC}"
            echo -e "  SNI: ${G}$sni${NC}  ShortID: ${G}$sid${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_server_config "$uuid" "$port" "$privkey" "$pubkey" "$sid" "$sni"
            ;;
        vless-xhttp)
            local uuid=$(gen_uuid) sid=$(gen_sid) sni=$(gen_sni) path="/"
            local keys=$(xray x25519 2>/dev/null)
            [[ -z "$keys" ]] && { _err "密钥生成失败"; return 1; }
            local privkey=$(echo "$keys" | grep -iE "(PrivateKey|Private key)" | awk '{print $NF}')
            local pubkey=$(echo "$keys" | grep -iE "(Password|Public key)" | awk '{print $NF}')
            [[ -z "$privkey" || -z "$pubkey" ]] && { _err "密钥提取失败"; return 1; }
            
            echo ""
            _line
            echo -e "  ${C}VLESS+Reality+XHTTP 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}  UUID: ${G}${uuid:0:8}...${NC}"
            echo -e "  SNI: ${G}$sni${NC}  ShortID: ${G}$sid${NC}"
            echo -e "  Path: ${G}$path${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_vless_xhttp_server_config "$uuid" "$port" "$privkey" "$pubkey" "$sid" "$sni" "$path"
            ;;
        vless-ws)
            local uuid=$(gen_uuid) sni="bing.com" path="/vless"
            
            echo ""
            _line
            echo -e "  ${C}VLESS+WS+TLS 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}  UUID: ${G}${uuid:0:8}...${NC}"
            echo -e "  SNI: ${G}$sni${NC}  Path: ${G}$path${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_vless_ws_server_config "$uuid" "$port" "$sni" "$path"
            ;;
        vless-vision)
            local uuid=$(gen_uuid) sni="bing.com"
            
            echo ""
            _line
            echo -e "  ${C}VLESS-XTLS-Vision 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}  UUID: ${G}${uuid:0:8}...${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_vless_vision_server_config "$uuid" "$port" "$sni"
            ;;
        socks)
            local username=$(gen_password 8) password=$(gen_password) port=$(gen_port)
            
            echo ""
            _line
            echo -e "  ${C}SOCKS5 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}"
            echo -e "  用户名: ${G}$username${NC}"
            echo -e "  密码: ${G}$password${NC}"
            _line
            echo ""
            
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_socks_server_config "$username" "$password" "$port"
            ;;
        ss2022)
            # SS2022 加密方式选择
            echo ""
            _line
            echo -e "  ${W}选择 SS2022 加密方式${NC}"
            _line
            _item "1" "2022-blake3-aes-128-gcm ${D}(推荐, 16字节密钥)${NC}"
            _item "2" "2022-blake3-aes-256-gcm ${D}(更强, 32字节密钥)${NC}"
            _item "3" "2022-blake3-chacha20-poly1305 ${D}(ARM优化, 32字节密钥)${NC}"
            echo ""
            
            local method key_len
            while true; do
                read -rp "  选择加密 [1-3]: " enc_choice
                case $enc_choice in
                    1) method="2022-blake3-aes-128-gcm"; key_len=16; break ;;
                    2) method="2022-blake3-aes-256-gcm"; key_len=32; break ;;
                    3) method="2022-blake3-chacha20-poly1305"; key_len=32; break ;;
                    *) _err "无效选择" ;;
                esac
            done
            
            local password=$(head -c $key_len /dev/urandom 2>/dev/null | base64 -w 0)
            
            echo ""
            _line
            echo -e "  ${C}Shadowsocks 2022 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}"
            echo -e "  加密: ${G}$method${NC}"
            echo -e "  密钥: ${G}$password${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_ss2022_server_config "$password" "$port" "$method"
            ;;
        hy2)
            local password=$(gen_password) sni="bing.com"
            
            echo ""
            _line
            echo -e "  ${C}Hysteria2 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC} (UDP)"
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  伪装: ${G}$sni${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_hy2_server_config "$password" "$port" "$sni"
            ;;
        trojan)
            local password=$(gen_password) sni="bing.com"
            
            echo ""
            _line
            echo -e "  ${C}Trojan 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}"
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_trojan_server_config "$password" "$port" "$sni"
            ;;
        snell)
            # Snell PSK 需要随机生成
            local psk=$(head -c 16 /dev/urandom 2>/dev/null | base64 -w 0 | tr -d '/+=' | head -c 22)
            local version="4"
            
            echo ""
            _line
            echo -e "  ${C}Snell v4 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}"
            echo -e "  PSK: ${G}$psk${NC}"
            echo -e "  版本: ${G}v$version${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_snell_server_config "$psk" "$port" "$version"
            ;;
        tuic)
            local uuid=$(gen_uuid) password=$(gen_password) sni="bing.com"
            
            echo ""
            _line
            echo -e "  ${C}TUIC v5 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC} (UDP/QUIC)"
            echo -e "  UUID: ${G}${uuid:0:8}...${NC}"
            echo -e "  密码: ${G}$password${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_tuic_server_config "$uuid" "$password" "$port" "$sni"
            ;;
        anytls)
            local password=$(gen_password) sni="bing.com"
            
            echo ""
            _line
            echo -e "  ${C}AnyTLS 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}"
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_anytls_server_config "$password" "$port" "$sni"
            ;;
        snell-v5)
            local psk=$(gen_password) version="5"
            
            echo ""
            _line
            echo -e "  ${C}Snell v5 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}"
            echo -e "  PSK: ${G}$psk${NC}"
            echo -e "  版本: ${G}$version${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_snell_v5_server_config "$psk" "$port" "$version"
            ;;
    esac
    
    _info "创建服务..."
    create_service
    _info "启动服务..."
    
    # 保存当前安装的协议名（防止被后续函数中的循环变量覆盖）
    local current_protocol="$protocol"
    
    if start_services; then
        create_shortcut
        _dline
        _ok "服务端安装完成! 快捷命令: vless"
        _ok "协议: $(get_protocol_name $current_protocol)"
        _dline
        
        # UDP协议提示开放防火墙
        if [[ "$current_protocol" == "hy2" || "$current_protocol" == "tuic" ]]; then
            source "$CFG/${current_protocol}.info" 2>/dev/null
            echo ""
            _warn "重要: 请确保防火墙开放 UDP 端口 $port"
            echo -e "  ${D}# iptables 示例:${NC}"
            echo -e "  ${C}iptables -A INPUT -p udp --dport $port -j ACCEPT${NC}"
            echo -e "  ${D}# 或使用 ufw:${NC}"
            echo -e "  ${C}ufw allow $port/udp${NC}"
            echo ""
        fi
        
        # TUIC 协议需要客户端持有证书
        if [[ "$current_protocol" == "tuic" ]]; then
            echo ""
            _warn "TUIC v5 要求客户端必须持有服务端证书!"
            _line
            echo -e "  ${C}请在客户端执行以下命令下载证书:${NC}"
            echo ""
            echo -e "  ${G}mkdir -p /etc/vless-reality/certs${NC}"
            echo -e "  ${G}scp root@$(get_ipv4):$CFG/certs/server.crt /etc/vless-reality/certs/${NC}"
            echo ""
            echo -e "  ${D}或手动复制证书内容到客户端 /etc/vless-reality/certs/server.crt${NC}"
            _line
        fi
        
        # 显示刚安装的协议配置（不清屏）
        show_single_protocol_info "$current_protocol" false
    else
        _err "安装失败"
    fi
}


do_install_client() {
    # 检查是否有残留但无有效安装
    if check_installed; then
        local installed=$(get_installed_protocols)
        if [[ -z "$installed" ]]; then
            # 有残留文件但没有有效协议，自动清理
            _info "检测到残留文件，自动清理..."
            stop_services 2>/dev/null
            rm -rf "$CFG" 2>/dev/null
            systemctl disable vless-reality vless-tun vless-global vless-watchdog 2>/dev/null
            rm -f /etc/systemd/system/vless-*.service 2>/dev/null
            systemctl daemon-reload 2>/dev/null
        else
            _warn "已安装，请先卸载"
            return
        fi
    fi
    _header
    echo -e "  ${W}客户端安装向导${NC}"
    _line
    echo ""
    read -rp "  JOIN 码: " join_code
    [[ -z "$join_code" ]] && { _err "JOIN 码不能为空"; return; }

    local decoded=$(echo "$join_code" | base64 -d 2>/dev/null)
    [[ -z "$decoded" ]] && { _err "无效的 JOIN 码"; return; }

    # 解析不同协议的JOIN码
    local protocol_type server_ip port
    local uuid pubkey sid sni path password method psk version
    
    if [[ "$decoded" =~ ^REALITY-XHTTP\| ]]; then
        # REALITY-XHTTP|ip|port|uuid|pubkey|sid|sni|path
        IFS='|' read -r _ server_ip port uuid pubkey sid sni path <<< "$decoded"
        protocol_type="vless-xhttp"
    elif [[ "$decoded" =~ ^REALITY\| ]]; then
        # REALITY|ip|port|uuid|pubkey|sid|sni
        IFS='|' read -r _ server_ip port uuid pubkey sid sni <<< "$decoded"
        protocol_type="vless"
    elif [[ "$decoded" =~ ^VLESS-VISION\| ]]; then
        # VLESS-VISION|ip|port|uuid|sni
        IFS='|' read -r _ server_ip port uuid sni <<< "$decoded"
        protocol_type="vless-vision"
    elif [[ "$decoded" =~ ^VLESS-WS\| ]]; then
        # VLESS-WS|ip|port|uuid|sni|path
        IFS='|' read -r _ server_ip port uuid sni path <<< "$decoded"
        protocol_type="vless-ws"
    elif [[ "$decoded" =~ ^SS2022\| ]]; then
        # SS2022|ip|port|method|password
        IFS='|' read -r _ server_ip port method password <<< "$decoded"
        protocol_type="ss2022"
    elif [[ "$decoded" =~ ^TROJAN\| ]]; then
        # TROJAN|ip|port|password|sni
        IFS='|' read -r _ server_ip port password sni <<< "$decoded"
        protocol_type="trojan"
    elif [[ "$decoded" =~ ^HY2\| ]]; then
        # HY2|ip|port|password|sni
        IFS='|' read -r _ server_ip port password sni <<< "$decoded"
        protocol_type="hy2"
    elif [[ "$decoded" =~ ^SNELL\| ]]; then
        # SNELL|ip|port|psk|version
        IFS='|' read -r _ server_ip port psk version <<< "$decoded"
        protocol_type="snell"
    elif [[ "$decoded" =~ ^TUIC\| ]]; then
        # TUIC|ip|port|uuid|password|sni
        IFS='|' read -r _ server_ip port uuid password sni <<< "$decoded"
        protocol_type="tuic"
    elif [[ "$decoded" =~ ^ANYTLS\| ]]; then
        # ANYTLS|ip|port|password|sni
        IFS='|' read -r _ server_ip port password sni <<< "$decoded"
        protocol_type="anytls"
    elif [[ "$decoded" =~ ^SNELL-V5\| ]]; then
        # SNELL-V5|ip|port|psk|version
        IFS='|' read -r _ server_ip port psk version <<< "$decoded"
        protocol_type="snell-v5"
    else
        _err "无效的 JOIN 码格式"; return
    fi
    
    [[ -z "$server_ip" || -z "$port" ]] && { _err "JOIN 码解析失败"; return; }

    echo ""
    _line
    echo -e "  服务器: ${G}$server_ip:$port${NC}"
    echo -e "  协议: ${G}$(get_protocol_name $protocol_type)${NC}"
    _line
    
    _info "清理旧环境..."
    force_cleanup
    sync_time

    _info "检测网络环境..."
    local client_ipv4=$(get_ipv4) client_ipv6=$(get_ipv6)
    echo -e "  IPv4: ${client_ipv4:-${R}无${NC}}  IPv6: ${client_ipv6:-${R}无${NC}}"
    
    _info "测试服务器连通性..."
    local clean_ip=$(echo "$server_ip" | tr -d '[]')
    local conn_ok=false
    
    # UDP协议(hy2/tuic)无法用TCP测试，跳过或用ping测试
    if [[ "$protocol_type" == "hy2" || "$protocol_type" == "tuic" ]]; then
        _warn "UDP协议，跳过TCP端口测试"
        # 尝试ping测试基本连通性
        if ping -c 1 -W 3 "$clean_ip" &>/dev/null; then
            _ok "服务器可达 (ICMP)"
            conn_ok=true
        else
            _warn "ICMP不通，但UDP可能正常"
            conn_ok=true  # UDP协议继续安装
        fi
    else
        if timeout 5 bash -c "echo >/dev/tcp/$clean_ip/$port" 2>/dev/null; then
            _ok "连接成功"
            conn_ok=true
        else
            _err "连接失败"
            read -rp "  是否继续安装? [y/N]: " force
            [[ "$force" =~ ^[yY]$ ]] && conn_ok=true
        fi
    fi
    [[ "$conn_ok" != "true" ]] && return
    
    if [[ "$warp_enabled" == "true" ]]; then
        echo ""
        _warn "检测到WARP"
        echo -e "  ${G}1.${NC} 保留WARP (推荐)  ${G}2.${NC} 关闭WARP"
        read -rp "  请选择 [1-2]: " warp_choice
        if [[ "$warp_choice" == "2" ]]; then
            _info "关闭WARP..."
            command -v warp-cli &>/dev/null && { warp-cli disconnect &>/dev/null; warp-cli disable-always-on &>/dev/null; }
            systemctl stop warp-svc &>/dev/null; systemctl disable warp-svc &>/dev/null
            ip link del warp &>/dev/null || true
            warp_enabled=false
            _ok "WARP已关闭"
        fi
    fi
    
    # Snell 客户端不支持 TUN/全局模式
    local mode
    if [[ "$protocol_type" == "snell" || "$protocol_type" == "snell-v5" ]]; then
        _warn "Snell 协议仅支持 Surge/Clash 等客户端"
        mode="socks"
    else
        echo ""
        _line
        _item "1" "TUN 网卡"
        _item "2" "全局代理 (iptables)"
        _item "3" "SOCKS5代理"
        echo ""
        while true; do
            read -rp "  选择模式 [1-3]: " choice
            case $choice in
                1) mode="tun"; break ;;
                2) mode="global"; break ;;
                3) mode="socks"; break ;;
                *) _err "无效选择" ;;
            esac
        done
    fi

    echo ""
    install_deps || return
    
    # 根据协议安装对应软件
    case "$protocol_type" in
        vless|vless-xhttp|vless-ws|vless-vision|ss2022|trojan)
            install_xray || return
            ;;
        hy2)
            install_hysteria || return
            ;;
        snell)
            _warn "Snell 客户端需要手动安装 Surge/Clash"
            ;;
        snell-v5)
            _warn "Snell v5 客户端需要手动安装 Surge/Clash"
            ;;
        tuic)
            install_tuic "client" || return
            ;;
        anytls)
            install_anytls || return
            ;;
    esac
    
    # TUN模式需要安装tun2socks
    if [[ "$mode" == "tun" && "$protocol_type" != "snell" && "$protocol_type" != "snell-v5" ]]; then
        install_tun2socks || { _err "tun2socks 安装失败，无法使用TUN模式"; return 1; }
    fi
    
    mkdir -p "$CFG"
    echo "$mode" > "$CFG/mode"
    
    _info "生成配置..."
    # 根据协议生成客户端配置
    case "$protocol_type" in
        vless)
            gen_client_config "vless" "$server_ip" "$port" "$uuid" "$pubkey" "$sid" "$sni"
            save_node "默认_${server_ip}_${port}" "vless" "$server_ip" "$port" "$uuid" "$pubkey" "$sid" "$sni"
            ;;
        vless-xhttp)
            gen_client_config "vless-xhttp" "$server_ip" "$port" "$uuid" "$pubkey" "$sid" "$sni" "$path"
            save_node "默认_${server_ip}_${port}" "vless-xhttp" "$server_ip" "$port" "$uuid" "$pubkey" "$sid" "$sni" "$path"
            ;;
        vless-vision)
            gen_client_config "vless-vision" "$server_ip" "$port" "$uuid" "$sni"
            save_node "默认_${server_ip}_${port}" "vless-vision" "$server_ip" "$port" "$uuid" "$sni"
            ;;
        vless-ws)
            gen_client_config "vless-ws" "$server_ip" "$port" "$uuid" "$sni" "$path"
            save_node "默认_${server_ip}_${port}" "vless-ws" "$server_ip" "$port" "$uuid" "$sni" "$path"
            ;;
        ss2022)
            gen_client_config "ss2022" "$server_ip" "$port" "$method" "$password"
            save_node "默认_${server_ip}_${port}" "ss2022" "$server_ip" "$port" "$method" "$password"
            ;;
        trojan)
            gen_client_config "trojan" "$server_ip" "$port" "$password" "$sni"
            save_node "默认_${server_ip}_${port}" "trojan" "$server_ip" "$port" "$password" "$sni"
            ;;
        hy2)
            gen_client_config "hy2" "$server_ip" "$port" "$password" "$sni"
            save_node "默认_${server_ip}_${port}" "hy2" "$server_ip" "$port" "$password" "$sni"
            ;;
        snell)
            gen_client_config "snell" "$server_ip" "$port" "$psk" "$version"
            save_node "默认_${server_ip}_${port}" "snell" "$server_ip" "$port" "$psk" "$version"
            ;;
        tuic)
            # TUIC v5 需要客户端持有服务端证书
            echo ""
            _warn "TUIC v5 要求客户端必须持有服务端证书"
            _line
            echo -e "  ${D}请确保已从服务端下载证书到本机${NC}"
            echo -e "  ${D}默认路径: /etc/vless-reality/certs/server.crt${NC}"
            echo ""
            read -rp "  证书文件路径 (直接回车使用默认): " cert_path
            [[ -z "$cert_path" ]] && cert_path="/etc/vless-reality/certs/server.crt"
            
            # 检查证书文件是否存在
            if [[ ! -f "$cert_path" ]]; then
                _err "证书文件不存在: $cert_path"
                echo ""
                echo -e "  ${C}请先从服务端下载证书:${NC}"
                echo -e "  ${G}mkdir -p /etc/vless-reality/certs${NC}"
                echo -e "  ${G}scp root@服务端IP:/etc/vless-reality/certs/server.crt /etc/vless-reality/certs/${NC}"
                echo ""
                return 1
            fi
            _ok "证书文件已找到: $cert_path"
            
            gen_client_config "tuic" "$server_ip" "$port" "$uuid" "$password" "$sni" "$cert_path"
            save_node "默认_${server_ip}_${port}" "tuic" "$server_ip" "$port" "$uuid" "$password" "$sni" "$cert_path"
            ;;
        anytls)
            gen_client_config "anytls" "$server_ip" "$port" "$password" "$sni"
            save_node "默认_${server_ip}_${port}" "anytls" "$server_ip" "$port" "$password" "$sni"
            ;;
        snell-v5)
            gen_client_config "snell-v5" "$server_ip" "$port" "$psk" "$version"
            save_node "默认_${server_ip}_${port}" "snell-v5" "$server_ip" "$port" "$psk" "$version"
            ;;
    esac
    
    local node_name="默认_${server_ip}_${port}"
    echo "$node_name" > "$CFG/current_node"
    
    create_scripts
    create_service
    
    _info "启动服务..."
    if start_services; then
        create_shortcut
        _dline
        echo -e "  ${G}✓${NC} 客户端安装完成!"
        echo -e "  快捷命令: ${G}vless${NC}  模式: ${G}$(get_mode_name $mode)${NC}"
        echo -e "  协议: ${G}$(get_protocol_name $protocol_type)${NC}"
        [[ "$protocol_type" != "snell" ]] && echo -e "  守护进程: ${G}Watchdog 已激活${NC}"
        _dline
        
        # UDP协议额外提示
        if [[ "$protocol_type" == "hy2" || "$protocol_type" == "tuic" ]]; then
            echo ""
            _warn "UDP协议注意事项:"
            echo -e "  ${D}1. 确保服务端防火墙已开放 UDP 端口${NC}"
            echo -e "  ${D}2. 云服务商安全组需允许 UDP 入站${NC}"
            echo -e "  ${D}3. 如连接失败，可尝试 SOCKS5 模式测试${NC}"
            echo ""
        fi
        
        [[ "$mode" != "socks" && "$protocol_type" != "snell" && "$protocol_type" != "snell-v5" ]] && { sleep 2; test_connection; }
    else
        _err "安装失败"
        # 清理残留文件
        _info "清理残留..."
        stop_services 2>/dev/null
        rm -rf "$CFG" 2>/dev/null
        systemctl disable vless-reality vless-tun vless-global vless-watchdog 2>/dev/null
        rm -f /etc/systemd/system/vless-*.service 2>/dev/null
        systemctl daemon-reload 2>/dev/null
    fi
}

show_status() {
    local installed=$(get_installed_protocols)
    if [[ -n "$installed" ]]; then
        local role=$(get_role) mode=$(get_mode)
        local status_icon status_text
        
        # 统计协议数量
        local protocol_count=$(echo "$installed" | wc -l)
        local xray_protocols=$(get_xray_protocols)
        local independent_protocols=$(get_independent_protocols)
        
        # 检查服务运行状态
        local xray_running=false
        local independent_running=0 independent_total=0
        
        # 检查 Xray 服务状态
        if [[ -n "$xray_protocols" ]]; then
            if svc status vless-reality; then
                xray_running=true
            fi
        fi
        
        # 检查独立协议服务状态
        local ind_proto
        for ind_proto in $independent_protocols; do
            ((independent_total++))
            if svc status "vless-${ind_proto}"; then
                ((independent_running++))
            fi
        done
        
        # 确定整体状态
        local xray_count=0
        [[ -n "$xray_protocols" ]] && xray_count=$(echo "$xray_protocols" | wc -l)
        local running_protocols=0
        
        if [[ "$xray_running" == "true" ]]; then
            running_protocols=$xray_count
        fi
        running_protocols=$((running_protocols + independent_running))
        
        if is_paused; then
            status_icon="${Y}⏸${NC}"; status_text="${Y}已暂停${NC}"
        elif [[ $running_protocols -eq $protocol_count ]]; then
            status_icon="${G}●${NC}"; status_text="${G}运行中${NC}"
        elif [[ $running_protocols -gt 0 ]]; then
            status_icon="${Y}●${NC}"; status_text="${Y}部分运行${NC} (${running_protocols}/${protocol_count})"
        else
            status_icon="${R}●${NC}"; status_text="${R}已停止${NC}"
        fi
        
        echo -e "  状态: $status_icon $status_text"
        echo -e "  角色: ${C}$([ "$role" == "server" ] && echo "服务端" || echo "客户端")${NC}"
        
        # 显示协议概要
        if [[ $protocol_count -eq 1 ]]; then
            source "$CFG/${installed}.info" 2>/dev/null
            echo -e "  协议: ${C}$(get_protocol_name $installed)${NC}"
            echo -e "  端口: ${C}$port${NC}"
        else
            echo -e "  协议: ${C}多协议 (${protocol_count}个)${NC}"
            # 显示每个协议和端口
            for proto in $installed; do
                local proto_port=""
                if [[ -f "$CFG/${proto}.info" ]]; then
                    source "$CFG/${proto}.info"
                    proto_port="$port"
                fi
                echo -e "    ${G}•${NC} $(get_protocol_name $proto) ${D}- 端口: ${proto_port}${NC}"
            done
        fi
        if [[ "$role" == "client" ]]; then
            echo -e "  模式: ${C}$(get_mode_name $mode)${NC}"
            source "$CFG/info" 2>/dev/null
            echo -e "  服务器: ${C}$server_ip:$port${NC}"
            if [[ "$DISTRO" != "alpine" && "$(systemctl is-active vless-watchdog)" == "active" ]]; then
                echo -e "  守护: ${G}Watchdog 运行中${NC}"
            fi
        fi
    else
        echo -e "  状态: ${D}○ 未安装${NC}"
    fi
}

main_menu() {
    check_root
    create_shortcut  # 确保快捷命令可用
    
    while true; do
        _header
        echo ""
        show_status
        echo ""
        _line
        
        local installed=$(get_installed_protocols)
        if [[ -n "$installed" ]]; then
            local role=$(get_role)
            if [[ "$role" == "server" ]]; then
                # 多协议服务端菜单
                _item "1" "安装新协议 (多协议共存)"
                _item "2" "查看所有协议配置"
                _item "3" "管理协议服务"
                _item "4" "BBR 网络优化"
                _item "5" "卸载指定协议"
                _item "6" "完全卸载"
            else
                # 客户端菜单保持不变
                _item "1" "查看节点信息"
                _item "2" "切换代理模式"
                _item "3" "测试连接"
                _item "4" "添加节点"
                _item "5" "切换节点"
                _item "6" "删除节点"
                is_paused && _item "7" "恢复服务" || _item "7" "暂停服务"
                _item "8" "重启服务"
                _item "9" "卸载"
            fi
        else
            _item "1" "安装服务端"
            _item "2" "安装客户端 (JOIN码)"
        fi
        _item "0" "退出"
        _line
        

        read -rp "  请选择: " choice || exit 0
        
        if [[ -n "$installed" ]]; then
            local role=$(get_role)
            if [[ "$role" == "server" ]]; then
                # 多协议服务端菜单处理
                case $choice in
                    1) do_install_server ;;  # 安装新协议
                    2) show_all_protocols_info ;;  # 查看所有协议配置
                    3) manage_protocol_services ;;  # 管理协议服务
                    4) enable_bbr ;;  # BBR 网络优化
                    5) uninstall_specific_protocol ;;  # 卸载指定协议
                    6) do_uninstall ;;  # 完全卸载
                    0) exit 0 ;;
                    *) _err "无效选择" ;;
                esac
            else
                # 客户端菜单处理保持不变
                case $choice in
                    1) show_client_info ;;
                    2) do_switch_mode ;;
                    3) test_connection ;;
                    4) do_add_node ;;
                    5) do_switch_node ;;
                    6) do_delete_node ;;
                    7) is_paused && { _info "恢复服务..."; start_services && _ok "已恢复"; } || { _info "暂停服务..."; stop_services; touch "$CFG/paused"; _ok "已暂停"; } ;;
                    8) _info "重启服务..."; stop_services; sleep 1; start_services && _ok "重启完成" ;;
                    9) do_uninstall ;;
                    0) exit 0 ;;
                    *) _err "无效选择" ;;
                esac
            fi
        else
            case $choice in
                1) do_install_server ;;
                2) do_install_client ;;
                0) exit 0 ;;
                *) _err "无效选择" ;;
            esac
        fi
        _pause
    done
}

main_menu