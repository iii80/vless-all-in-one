# 🚀 多协议代理一键部署脚本 v2.0

一个简单易用的多协议代理部署脚本，支持 **12 种主流协议**，服务端/客户端一键安装，适用于 Alpine、Debian、Ubuntu、CentOS 等 Linux 发行版。

> 🙏 **声明**：本人只是一个搬运工，脚本灵感来源于网络上的各种优秀项目，特别感谢 [mack-a/v2ray-agent](https://github.com/mack-a/v2ray-agent) 八合一脚本的启发。

---

## 🆕 v2.0 重大更新

### 🔥 多协议并存
- 支持同时部署多个代理协议，无需卸载重装
- Xray 系协议自动合并为单一配置，共享核心进程
- 独立协议 (HY2/TUIC/Snell 等) 各自独立运行
- 统一的协议注册/注销管理机制

### ⚡ BBR 拥塞控制优化
- 自动检测并启用 BBR 内核模块
- 显著提升网络传输性能和稳定性
- 降低延迟，提高吞吐量

### 🛡️ 端口冲突检测
- 安装时自动检测 TCP/UDP 端口占用
- 避免多协议部署时的端口冲突
- 智能分配可用端口

### 📦 架构升级
- 每个协议独立配置文件，支持热加载
- 动态生成 Xray 多 inbounds 配置
- 增强的多协议服务状态检测

---

## ✨ 支持协议

| # | 协议 | 特点 | 推荐场景 |
|---|------|------|----------|
| 1 | **VLESS + Reality** | 抗封锁能力强，无需域名 | 🌟 首选推荐 |
| 2 | **VLESS + Reality + XHTTP** | 多路复用，性能更优 | 高并发场景 |
| 3 | **VLESS + WS + TLS** | CDN 友好，可套 CF | 被墙 IP 救活 |
| 4 | **VLESS-XTLS-Vision** | Vision 流控，TLS 伪装 | 稳定传输 |
| 5 | **SOCKS5** | 经典代理协议，Telegram 支持 | 🔥 通用性强 |
| 6 | **Shadowsocks 2022** | 新版加密，性能好 | SS 用户迁移 |
| 7 | **Hysteria2** | UDP 加速，高速传输 | 游戏/视频 |
| 8 | **Trojan** | 伪装 HTTPS 流量 | 传统方案 |
| 9 | **Snell v4** | Surge 专用协议 | iOS/Mac 用户 |
| 10 | **Snell v5** | Surge 5.0 新版协议，自动更新 | 最新 Surge 用户 |
| 11 | **AnyTLS** | 多协议 TLS 代理 | 抗审查能力强 |
| 12 | **TUIC v5** | QUIC 协议，低延迟 | 新兴协议 |

---

## 🎯 核心特性

- 🔧 **一键部署** - 服务端/客户端快速安装，无需手动配置
- 🔀 **多协议并存** - 同时运行多个协议，无需卸载重装 (v2.0 新增)
- ⚡ **BBR 优化** - 自动启用 BBR 拥塞控制，提升传输性能 (v2.0 新增)
- 🔗 **JOIN 码连接** - 服务端生成 JOIN 码，客户端一键导入
- 🌐 **双栈支持** - 自动检测 IPv4/IPv6，分别生成连接信息
- 📱 **多种导入** - JOIN 码、分享链接、二维码
- 🔄 **多节点管理** - 添加、切换、删除节点，自动测速
- 🛡️ **三种代理模式** - TUN 网卡 / 全局代理 / SOCKS5
- 🐕 **Watchdog 守护** - 自动监控，断线重连
- 🔒 **FwMark 防死锁** - 内核级流量标记，防止代理环路
- 🌍 **WARP 兼容** - 自动检测并适配 WARP 网络环境
- 📲 **Telegram 集成** - SOCKS5 一键导入 Telegram 代理
- 🔄 **自动版本更新** - Snell v5 自动获取最新版本
- 🛠️ **详细错误提示** - 依赖安装失败时显示具体错误信息
- 🚫 **端口冲突检测** - 自动检测端口占用，避免冲突 (v2.0 新增)

---

## 📋 系统要求

### 支持的系统
- Debian 9+ / Ubuntu 18.04+
- CentOS 7+ 
- Alpine Linux 3.12+

### 架构支持
- x86_64 (amd64)
- ARM64 (aarch64)

---

## 🚀 快速开始

### 一键安装

```bash
wget -O vless.sh https://raw.githubusercontent.com/Chil30/vless-all-in-one/main/vless.sh && chmod +x vless.sh && bash vless.sh
```

### 服务端安装

```bash
vless
# 选择 1) 安装服务端
# 选择协议 (推荐 1-VLESS+Reality)
# 确认安装
```

安装完成后显示：
- **JOIN 码** - 复制给客户端使用
- **分享链接** - 可导入 v2rayN、Clash、小火箭等
- **二维码** - 手机扫码导入

### 客户端安装

```bash
vless
# 选择 2) 安装客户端 (JOIN码)
# 粘贴服务端的 JOIN 码
# 选择代理模式 (推荐 TUN)
```

### 快捷命令

首次运行脚本后自动创建快捷命令：
```bash
vless  # 在任意目录直接运行管理菜单
```

快捷命令原理：
- 脚本自动复制到 `/usr/local/bin/vless.sh`
- 创建软链接 `/usr/local/bin/vless` → `/usr/local/bin/vless.sh`
- 由于 `/usr/local/bin` 在系统 PATH 中，可全局调用

---

## 📱 客户端推荐

| 平台 | 推荐客户端 | 支持协议 |
|------|-----------|----------|
| **Windows** | [V2rayN](https://github.com/2dust/v2rayN) | 全部 |
| **Windows** | [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev) | 除 Snell 系列 |
| **macOS** | [V2rayU](https://github.com/yanue/V2rayU) | 全部 |
| **macOS** | [Surge](https://nssurge.com/) | 全部 (付费) |
| **iOS** | [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118) | 全部 (付费) |
| **iOS** | [Surge](https://apps.apple.com/app/surge-5/id1442620678) | 全部 (付费) |
| **Android** | [V2rayNG](https://github.com/2dust/v2rayNG) | 全部 |
| **Android** | [NekoBox](https://github.com/MatsuriDayo/NekoBoxForAndroid) | 全部 |
| **Linux** | 本脚本客户端模式 | 全部 |

---

## 🖥️ 界面预览

### 主菜单
```
═════════════════════════════════════════════
      多协议代理 一键部署 v2.0
      作者: Chil30  快捷命令: vless
      https://github.com/Chil30/vless-all-in-one
═════════════════════════════════════════════
  状态: ○ 未安装
─────────────────────────────────────────────
  1) 部署服务端
  2) 加入服务端 (JOIN码)
  0) 退出
─────────────────────────────────────────────
```

### 协议选择
```
─────────────────────────────────────────────
  选择代理协议
─────────────────────────────────────────────
  1) VLESS + Reality (推荐, 抗封锁)
  2) VLESS + Reality + XHTTP (多路复用)
  3) VLESS + WS + TLS (CDN友好)
  4) VLESS-XTLS-Vision (Vision流控)
  5) SOCKS5 (经典代理)
  6) Shadowsocks 2022 (新版加密)
  7) Hysteria2 (UDP加速, 高速)
  8) Trojan (伪装HTTPS)
  9) Snell v4 (Surge专用)
  10) Snell v5 (Surge 5.0新版)
  11) AnyTLS (多协议TLS代理)
  12) TUIC v5 (QUIC协议)
```

### 服务端运行中
```
═════════════════════════════════════════════
      多协议代理 一键部署 v2.0
      作者: Chil30  快捷命令: vless
      https://github.com/Chil30/vless-all-in-one
═════════════════════════════════════════════
  状态: ● 运行中
  角色: 服务端
  协议: VLESS+Reality, Hysteria2  (多协议并存)
  端口: 443, 8443
─────────────────────────────────────────────
  1) 查看配置/JOIN码
  2) 添加协议 (多协议并存)
  3) 管理协议
  4) 暂停服务
  5) 重启服务
  6) 卸载
  0) 退出
─────────────────────────────────────────────
```

---

## 🔧 代理模式说明

### 1️⃣ TUN 网卡模式 (推荐)
```
创建虚拟网卡 tun0，修改系统路由表
✅ 全局透明代理，所有应用自动走代理
✅ 支持 TCP/UDP
❌ LXC 容器可能不支持
```

### 2️⃣ 全局代理模式 (iptables)
```
使用 iptables 劫持流量
✅ 兼容性好
✅ 支持纯 IPv6 + WARP 环境
❌ 仅代理 TCP 流量
```

### 3️⃣ SOCKS5 模式
```
仅启动 SOCKS5 代理 (127.0.0.1:10808)
✅ 无需特殊权限，兼容性最好
❌ 需要手动配置应用使用代理
```

---

## 🔀 多协议并存使用指南 (v2.0 新功能)

### 协议分类

脚本将协议分为两类进行管理：

| 类型 | 协议 | 说明 |
|------|------|------|
| **Xray 协议组** | VLESS, VLESS-XHTTP, VLESS-WS, VLESS-Vision, Trojan, SOCKS5, SS2022 | 共享 Xray 核心，自动合并 inbounds |
| **独立协议组** | Hysteria2, TUIC, Snell v4, Snell v5, AnyTLS | 各自独立进程运行 |

### 添加多个协议

```bash
# 1. 首次安装一个协议
./vless.sh
# 选择 1) 部署服务端 → 选择 VLESS+Reality

# 2. 添加更多协议
./vless.sh
# 选择 2) 添加协议 → 选择 Hysteria2
# 继续添加...
```

### 查看已安装协议

```bash
./vless.sh
# 选择 3) 管理协议 → 显示所有已安装协议及状态
```

### 协议配置存储

每个协议的配置独立存储：
```
/etc/vless-reality/
├── installed_protocols   # 已安装协议列表
├── vless.info            # VLESS 配置
├── hy2.info              # HY2 配置
├── config.json           # Xray 合并配置
└── ...
```

### 注意事项

- Xray 协议组共享同一个 Xray 进程，配置自动合并
- 独立协议各自运行独立进程
- 卸载单个协议不影响其他协议
- 端口自动检测，避免冲突

---

## 📖 使用指南

### 服务端菜单
```
1) 查看配置/JOIN码  - 显示所有协议连接信息
2) 添加协议        - 添加新协议 (多协议并存)
3) 管理协议        - 查看/卸载已安装协议
4) 暂停/恢复服务    - 临时停止或恢复
5) 重启服务        - 重启所有代理服务
6) 卸载           - 完全卸载
```

### 客户端菜单
```
1) 查看节点信息    - 显示当前节点配置
2) 切换代理模式    - TUN/全局/SOCKS5 切换
3) 测试连接       - 测试代理是否正常
4) 添加节点       - 添加新的服务器节点
5) 切换节点       - 切换到其他节点（显示延迟）
6) 删除节点       - 删除已保存的节点
7) 暂停/恢复服务   - 临时停止或恢复
8) 重启服务       - 重启代理服务
9) 卸载          - 完全卸载
```

### SOCKS5 代理使用

```bash
# 方法1: 命令行指定
curl -x socks5://127.0.0.1:10808 ip.sb

# 方法2: 环境变量 (推荐)
export all_proxy=socks5://127.0.0.1:10808
curl ip.sb

# 永久配置
echo 'export all_proxy=socks5://127.0.0.1:10808' >> ~/.bashrc
source ~/.bashrc
```

### 📲 SOCKS5 Telegram 集成

SOCKS5 协议特别支持 Telegram 代理链接格式，安装完成后会同时提供两种链接：

```bash
# Telegram 代理链接 (一键导入)
https://t.me/socks?server=1.2.3.4&port=1080&user=username&pass=password

# 传统 SOCKS5 链接 (通用客户端)
socks5://username:password@1.2.3.4:1080#SOCKS5-1.2.3.4
```

**Telegram 使用方法**：
1. 点击 Telegram 代理链接
2. Telegram 自动弹出代理设置对话框
3. 点击"启用代理"即可使用

---

## 🌐 网络环境适配

| 服务端 | 客户端 | 可用模式 | 备注 |
|--------|--------|----------|------|
| IPv4 | IPv4 | TUN/全局/SOCKS5 | ✅ 最佳 |
| IPv6 | IPv6 | TUN/全局/SOCKS5 | ✅ 直连 |
| 双栈 | IPv4 | TUN/全局/SOCKS5 | 用 IPv4 JOIN码 |
| 双栈 | IPv6 | TUN/全局/SOCKS5 | 用 IPv6 JOIN码 |
| IPv4 | IPv6+WARP | 全局/SOCKS5 | 需要 WARP |

---

## ❓ 常见问题

### Q: 安装失败，提示依赖安装失败
```bash
# Debian/Ubuntu
apt update && apt install -y curl jq unzip iproute2

# CentOS
yum install -y curl jq unzip iproute

# Alpine
apk add curl jq unzip iproute2
```

### Q: 客户端连接失败
1. 确认服务端正在运行
2. 检查防火墙是否放行端口
3. 确认网络类型匹配（IPv4/IPv6）

### Q: TUN 模式启动失败
- LXC 容器不支持 TUN，请使用全局代理或 SOCKS5 模式
- 检查 TUN 模块：`ls -la /dev/net/tun`

### Q: 如何查看日志
```bash
journalctl -u vless-reality -f
```

---

## 📁 文件位置

```
/etc/vless-reality/
├── config.json           # Xray 主配置文件 (多协议合并)
├── installed_protocols   # 已安装协议列表 (v2.0 新增)
├── vless.info            # VLESS 协议配置
├── vless-xhttp.info      # VLESS-XHTTP 协议配置
├── hy2.info              # Hysteria2 协议配置
├── trojan.info           # Trojan 协议配置
├── ... (其他协议 .info)
├── join.txt              # JOIN 码和分享链接
├── mode                  # 当前代理模式
├── role                  # 角色 (server/client)
├── protocol              # 主协议标识
├── nodes/                # 保存的节点目录
└── certs/                # 证书目录 (部分协议)
```

---

## 🙏 致谢

本脚本的诞生离不开以下优秀的开源项目，在此表示衷心的感谢：

### 灵感来源
- [mack-a/v2ray-agent](https://github.com/mack-a/v2ray-agent) - 八合一共存脚本，本脚本的主要灵感来源

### 核心组件
- [XTLS/Xray-core](https://github.com/XTLS/Xray-core) - 强大的代理核心引擎
- [XTLS/REALITY](https://github.com/XTLS/REALITY) - Reality 协议实现
- [xjasonlyu/tun2socks](https://github.com/xjasonlyu/tun2socks) - TUN 转 SOCKS5 工具
- [apernet/hysteria](https://github.com/apernet/hysteria) - Hysteria2 协议
- [EAimTY/tuic](https://github.com/EAimTY/tuic) - TUIC 协议
- [shadowsocks/shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust) - Shadowsocks 2022
- [icpz/snell-server-reversed](https://github.com/icpz/snell-server-reversed) - Snell 协议
- [anytls/anytls-go](https://github.com/anytls/anytls-go) - AnyTLS 协议

### 特别感谢
- 所有为网络自由做出贡献的开发者们
- 各种技术论坛和社区的分享者们

---

## ⚠️ 免责声明

- 本脚本仅供学习交流使用
- 请遵守当地法律法规
- 作者不对使用本脚本造成的任何后果负责
- 本人只是一个搬运工，整合了网络上的优秀资源

---

## 📄 许可证

MIT License

---

## 📝 更新日志

### v2.0 (2025-12-23)
- 🚀 **重大更新: 多协议并存**
  - 支持同时部署多个代理协议，无需卸载重装
  - Xray 系协议 (VLESS/Trojan/SOCKS/SS2022) 自动合并 inbounds
  - 独立协议 (HY2/TUIC/Snell/AnyTLS) 各自独立服务运行
  - 新增协议注册/注销管理机制
  - 统一的已安装协议列表管理
- ⚡ **BBR 拥塞控制优化**
  - 自动检测并启用 BBR 内核模块
  - 提升网络传输性能和稳定性
- 🔧 **功能优化**
  - **端口冲突检测**: gen_port() 自动检测 TCP/UDP 端口占用
  - **配置分离存储**: 每个协议独立 .info 文件
  - **动态配置生成**: Xray 多 inbounds 自动合并
  - **增强状态检测**: 支持多协议端口监听检测
- 📦 **架构改进**
  - 协议分类管理: Xray 协议组 / 独立协议组

### v1.2 (2025-12-22)
- ✨ **新增协议支持**
  - 新增 **SOCKS5** 协议支持 (经典代理协议，通用性强)
- 🔧 **功能优化**
  - **详细错误提示**: 依赖安装失败时显示具体错误信息和包名

### v1.1 (2025-12-22)
- ✨ **协议扩展**
  - 添加 Snell v5 和 AnyTLS 基础支持
  - 调整协议菜单顺序

### v1.0 (2025-12-21)
- 🎉 **首次发布**
  - 支持 9 种主流代理协议
  - 服务端/客户端一键部署
  - JOIN 码连接方式
  - 多节点管理功能
  - 三种代理模式支持

---

**⭐ 如果觉得有用，欢迎 Star！**
