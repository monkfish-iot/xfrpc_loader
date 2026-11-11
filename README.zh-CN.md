# xfrpc_loader

[English](README.md) | 简体中文

对 **xfrpc**（FRP 客户端）**非侵入式**的外部辅助守护进程，帮助你在**安全、
批量**的场景下，让多台 OpenWrt 设备自动接入 frps 服务器，由 Monkfish 云平台
统一管理与鉴权，并通过 FRP 隧道安全地远程访问每台设备的 Web 管理界面。

> - 语言：C（C11）· 平台：OpenWrt · 许可证：Apache-2.0
> - 依赖 xfrpc 版本：**要求 xfrpc 5.x 及以上**
> - 预编译 xfrpc 客户端包：<https://github.com/monkfish-iot/xfrpc5>
> - 配套服务端：`frps_helper`（见同一组织仓库）
> - **项目文档网站：<http://monkfish.cn>**

---

## 它解决什么问题

当你有大量分散的 OpenWrt 路由器需要**远程管理**时，传统做法每台设备逐一
手动配置 frp、分配固定地址、维护各自的管理密码，既繁琐又不安全。

`xfrpc_loader` 以**外部辅助**方式（不改动 xfrpc 本身）自动完成：

1. **自动接入**：设备启动后自动向管理服务器发起带签名的「加入请求」，
   建立会话并自动生成 `xfrpc.ini`、拉起 xfrpc 子进程接入 frps。
2. **批量管理**：服务器端集中登记设备（MAC / device_id），可统一授权、
   禁用。
3. **动态域名解析**：每台设备在 frps 上获得随会话轮换的动态子域名，
   远程用户凭域名访问，无需记住每台设备的 IP。
4. **集中密码安全托管**：配合 `frps_helper` 为设备 Web 登录提供**集中
   用户鉴权**，把散落在各设备的管理密码集中、安全地统一管理。

一句话：**设备侧轻量、免改造；管理侧集中、安全、可扩展。**

## 核心特性

| 特性 | 说明 |
|------|------|
| **非侵入式** | 不改动 xfrpc 二进制与协议，仅作为外部进程生成配置并拉起 xfrpc 子进程 |
| **双向身份认证** | 带签名的 join：设备侧公钥钉扎、服务器侧根 CA 校验证书链，签名原文绑定 nonce 与时间戳（防抢注、防重放） |
| **自动会话管理** | 加入 → 会话 → 状态上报 → 失败按指数退避重连，全程无人值守 |
| **动态域名映射** | 每台设备的子域名随会话 ID 轮换，地址随 session 漂移，防地址被长期锁定（防探测） |
| **隧道/直连双模式** | 服务端通过 join 响应下发 `frpc_mode`：`1`（缺省）启动 xfrpc 走隧道；`0` 不启动 xfrpc，仅 status 保活，可用 `http://<local_if_IP>:8765` 直连 LuCI |
| **集中用户鉴权** | 内嵌 auth server（127.0.0.1:8888），配合 nginx `auth_request` 与 `frps_helper` 提供统一 Web 登录鉴权 |
| **安全密码轮换** | 可选在每次登录成功后轮换本机 LuCI root 密码，RSA 加密落盘 |
| **控制通道** | 通过 Unix 套接字（`webauthd-control/v1`）向 `webauthd` 下发期望状态（Portal 地址、RADIUS 参数、租户 ID），generation/租约机制 + ACK 确认 |
| **时间同步** | join/status 响应中服务器下发电时钟与时区 |
| **轻量依赖** | 运行时只需 libevent2 / libcurl / json-c / OpenSSL，不依赖 libuci/libyaml |

## 系统构成

```
┌──────────────────────────── 云端 ────────────────────────────┐
│                                                              │
│   frps_helper（管理 + 鉴权服务器）                            │
│   ├─ 管理接口    :6999  (join / status)                      │
│   ├─ 远程认证    :6999  (/api/v1/auth)                       │
│   └─ frps        :7000  (接收 xfrpc 隧道)                    │
│   （本仓库不包含，见 frps_helper 仓库）                        │
└──────────────────────────────┬───────────────────────────────┘
                               │ xfrpc 隧道 / 本地域名解析
                               ▼
┌────────────────────────── OpenWrt 设备 ──────────────────────┐
│                                                              │
│   xfrpc_loader（本仓库）                                      │
│   ├─ 主守护进程  : 加入/会话/状态上报                         │
│   ├─ xfrpc 管理  : 生成 ini + 拉起 xfrpc 子进程               │
│   ├─ auth server :8888（仅 127.0.0.1）                       │
│   ├─ 控制套接字  : webauthd-control/v1（对接 webauthd）       │
│   └─ nginx :8765 : 反代 LuCI + auth_request 集中鉴权          │
│                                                              │
│   xfrpc : 隧道客户端（外部二进制，xfrpc5 提供）                │
│   LuCI  : uhttpd :8000（OpenWrt Web UI）                     │
└──────────────────────────────────────────────────────────────┘
```

### 端口速查

| 端口 | 组件 | 绑定地址 | 方向 |
|------|------|----------|------|
| 8888 | auth server | 127.0.0.1 | 仅本机 |
| 8765 | nginx（管理入口反代） | 随 `frpc_mode` 切换 | 隧道模式 127.0.0.1 / 直连模式 any |
| 8000 | LuCI（uhttpd） | 0.0.0.0 | 本机 |
| 6999 | frps_helper 管理/认证 | 云端 | 对外 |
| 7000 | xfrpc 服务端（frps） | 云端 | 对外 |

> auth server 仅监听 `127.0.0.1`，外部不可直连，必须经 nginx
> `auth_request` 触发认证。8765 虚拟主机同时屏蔽了 LuCI RPC 登录与
> 改密接口的直连访问。隧道/直连两种绑定地址的模板见 `src/conf/`。

## 工作原理

守护进程基于 libevent2 事件驱动，核心是一个有限状态机：

```
INIT --> JOINING --> RUNNING --> REJOIN --> JOINING
  |         |          |                    （指数退避
  v         v          v                      重试）
 TERM <-----+----------+-------- (SIGTERM/SIGINT)
```

1. **INIT**——加载配置（`/tmp/xfrpc_loader.json`，由 init 脚本从 UCI
   渲染生成），采集设备信息，启动认证服务。
2. **JOINING**——向云服务器发送带签名的 join 请求。成功后服务器返回
   会话 ID、xfrpc 服务器地址、可选的服务器证书链以及可选的
   RADIUS/Portal 参数。
3. **RUNNING**——按生成的 INI 拉起 `xfrpc`，周期性上报状态，应用服务器
   下发的时区，并处理本地认证请求。
4. **REJOIN**——状态上报失败或 `xfrpc` 退出时，拆除隧道并以指数退避
   重新加入。
5. **TERM**——停止 `xfrpc`、认证服务与控制通道，清理后退出。

## 快速开始

### 前置条件

- OpenWrt 设备上已部署 **xfrpc 5.x**（`/usr/bin/xfrpc`），可使用
  [monkfish-iot/xfrpc5](https://github.com/monkfish-iot/xfrpc5) 的
  预编译包。
- 云端 `frps_helper` 已运行（管理接口 + 认证接口 + frps）。
- 设备可访问管理服务器地址。

### 作为 OpenWrt 软件包构建

将本仓库放入 OpenWrt SDK/源码树并启用：

```sh
cp -r xfrpc_loader openwrt/package/xfrpc_loader/
cd openwrt
make menuconfig          # 在 "Monkfish Softwares" 下启用 xfrpc_loader
make -j$(nproc) V=s package/xfrpc_loader/compile
```

生成的 `xfrpc_loader_<版本>_<架构>.ipk` 可用 `opkg install` 安装。

构建期选项（修改 `Makefile` 顶部）：

| 变量                | 默认值 | 含义 |
|---------------------|--------|------|
| `LOCAL_SKEY`        | `1`    | `1`：开源本地模式，密钥由进程内 libcrypto 首次启动时生成（存于 `/etc/config/skey/`），依赖 `openssl-util`；`0`：使用 `libskey` 静态库与产线烧录在 `/etc/skey/` 的设备材料（方案 D 公钥钉扎双向认证，运行时需固件自带根 CA `/etc/skey/ca.pem`）。 |
| `INSTALL_PASSWD_SH` | `0`    | `1`：额外安装 `show_luci_passwd.sh`，通过本地认证服务显示当前 LuCI 明文密码。 |

### 独立构建（开发调试）

```sh
cd src
make          # 生成 ./xfrpc_loader
make clean    # 清理构建产物
```

主机需安装 libevent2、libcurl、json-c、libskey 与 OpenSSL 的开发头文件。

### 安装到设备

```sh
scp packages/*/xfrpc_loader_*.ipk root@<设备IP>:/tmp/
opkg install /tmp/xfrpc_loader_*.ipk
opkg install libevent2 libcurl libjson-c libopenssl
```

### 最小配置

```sh
# 配置管理服务器（server_name 与 server_ip 至少填一个）
uci set xfrpc_loader.main.server_name='dm.example.com'
uci set xfrpc_loader.main.server_port='6999'
uci set xfrpc_loader.main.protocol='https'
uci commit xfrpc_loader

/etc/init.d/xfrpc_loader enable
/etc/init.d/xfrpc_loader start
```

验证：

```sh
logread | grep xfrpc_loader | tail -30
# 期望看到：join ok, session=... ; xfrpc started, pid=...
```

### 启用集中鉴权（配合 frps_helper）

```sh
uci set xfrpc_loader.auth.enabled='1'
uci set xfrpc_loader.auth.remote_host='auth.example.com'
uci set xfrpc_loader.auth.remote_port='6999'
uci set xfrpc_loader.auth.remote_path='/api/v1/auth'
uci commit xfrpc_loader
/etc/init.d/xfrpc_loader restart
```

启用后，远程用户通过 nginx:8765 访问 LuCI；`frps_helper` 集中校验用户
凭证并下发 token，`xfrpc_loader` 用该 token 换取 LuCI `sysauth` Cookie
实施登录。

## 仓库结构

```
Makefile                     OpenWrt 软件包 Makefile（构建入口）
files/
  xfrpc_loader.uci           默认 UCI 配置（/etc/config/xfrpc_loader）
  xfrpc_loader.init          procd init 脚本（/etc/init.d/xfrpc_loader）
  etc/nginx/conf.d/ubus.conf ubus/LuCI 隧道入口的 nginx 配置
  etc/uci-defaults/          sysupgrade 保留文件脚本（libskey 模式）
  skey_gen.sh                手工/调试用的密钥生成工具（不随包安装）
  show_luci_passwd.sh        显示当前 LuCI 明文密码的可选工具
src/                         守护进程 C 源码
  Makefile                   本机独立构建（开发用）
  conf/                      nginx 虚拟主机模板（隧道/直连模式）
  LICENSE                    Apache License 2.0
  NOTICE                     第三方组件声明
```

## 配置说明

配置通过 UCI 管理（`/etc/config/xfrpc_loader`），init 脚本将其渲染为
`/tmp/xfrpc_loader.json` 供守护进程读取。

### `main` 段

| 选项                 | 默认值      | 说明 |
|----------------------|-------------|------|
| `server_name`        | 空          | 云服务器域名（优先级高于 IP；与 IP 至少填一个） |
| `server_ip`          | `127.0.0.1` | 云服务器 IP |
| `server_port`        | `6999`      | 云服务器端口 |
| `protocol`           | `https`     | `http` / `https` |
| `local_if`           | `br-lan`    | 采集设备信息的本地接口（取 MAC/IP） |
| `join_timeout`       | `10`        | join 请求超时（秒） |
| `status_interval`    | `60`        | 状态上报间隔（秒） |
| `retry_interval`     | `5`         | 初始重试间隔（秒） |
| `max_retry_interval` | `300`       | 指数退避上限（秒） |
| `max_join_retries`   | `0`         | join 最大重试次数，`0` 为不限 |
| `time_sync_enabled`  | `1`         | 是否从服务器同步时钟/时区 |
| `time_sync_threshold`| `5`         | 触发同步的时钟偏差阈值（秒） |

### `auth` 段（Web 登录集中鉴权）

| 选项                    | 默认值         | 说明 |
|-------------------------|----------------|------|
| `enabled`               | `1`            | 是否启用本地认证服务 |
| `listen_port`           | `8888`         | 本地监听端口（回环） |
| `remote_proto`          | `https`        | 远程认证协议 |
| `remote_host`           | 空             | 远程认证地址（空则用 `server_name`） |
| `remote_port`           | `0`            | 远程认证端口（0 则用 `server_port`） |
| `remote_path`           | `/api/v1/auth` | 远程认证接口路径 |
| `remote_timeout`        | `10`           | 远程认证超时（秒） |
| `token_cache_ttl`       | `240`          | token 缓存时间（秒） |
| `token_retry_interval`  | `5`            | token 重试间隔（秒） |
| `modify_local_password` | `0`            | `0`：用默认账号密码锁用户；`1`：登录成功后轮换本机 LuCI 密码 |
| `default_username`      | `root`         | 本地登录用户名 |
| `default_password`      | `admin`        | 本地兜底密码 |

服务管理：

```sh
/etc/init.d/xfrpc_loader start|stop|restart
logread -e xfrpc_loader
```

## 安全说明

- auth server 仅监听本机回环地址，外部不可直连。
- 设备 root 密码 RSA 加密落盘，文件外泄无法直接使用。
- 设备动态域名随会话轮换，防止地址被长期锁定（防探测）。
- HTTPS 证书校验默认由 OpenWrt 的 curl 决定，生产环境建议配置受信任
  证书。

## 文档与相关仓库

- **项目文档网站：<http://monkfish.cn>**——系统架构、快速上手、服务端
  部署与接口规范等完整文档。
- [monkfish-iot/xfrpc5](https://github.com/monkfish-iot/xfrpc5)——
  预编译 xfrpc 客户端包（需 5.x）。
- `frps_helper`——配套云端管理 + 鉴权服务器（见同一组织仓库）。

## 运行时依赖

`libevent2`、`libcurl`、`libjson-c`、`libopenssl`，以及
`openssl-util`（默认 `LOCAL_SKEY=1` 模式）或 `skey`
（`LOCAL_SKEY=0` 模式）。运行时需要 `xfrpc` 二进制；安装 nginx 时作为
隧道入口的反向代理。

## 许可证

Copyright 2026 Monkfish。基于
[Apache License, Version 2.0](src/LICENSE) 发布。
第三方组件声明见 [src/NOTICE](src/NOTICE)。
