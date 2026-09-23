# xfrpc_loader

**[English](README.md)** / **中文**

对 **xfrpc** 客户端**非侵入式**的外部辅助系统，帮助你在**安全、批量**的场景下，让多台 OpenWrt 设备自动接入 frps 服务器，并由云端统一管理与鉴权。

> - 语言：C（标准 C11）
> - 平台：OpenWrt
> - 许可证：Apache-2.0
> - 依赖 xfrpc 的版本：**要求 xfrpc 5.x 及以上**
> - 配套客户端可执行包：`https://github.com/monkfish-iot/xfrpc5`
> - 配套服务端：`frps_helper`（见同一组织仓库）

---

## 一、它解决什么问题

当你有大量分散的 OpenWrt 路由器需要**远程管理**时，传统做法每个设备逐一手动配置 frp、分配固定地址、维护各自的管理密码，既繁琐又不安全。

`xfrpc_loader` 以**外部辅助**的方式（不改动 xfrpc 本身）自动完成：

1. **自动接入**：设备启动后自动向管理服务器发起「加入请求」，建立会话并自动生成 `xfrpc.ini`、拉起 xfrpc 子进程，接入 frps。
2. **批量管理**：服务器端集中登记设备（MAC / device_id），可统一授权、禁用。
3. **动态域名解析**：在 frps 上通过**本地域名系统**为每一台 OpenWrt 盒子分配**动态域名**，远程用户凭域名访问，无需记住每台设备的 IP。
4. **集中密码安全托管**：配合 `frps_helper`，为分散的 OpenWrt 提供 HTTP/HTTPS Web 登录的**集中用户鉴权**——把每台设备各自的管理密码集中、安全地统一管理，避免密码散落各处或硬编码在设备上。

一句话：**设备侧轻量、免改造；管理侧集中、安全、可扩展。**

---

## 二、核心特性

| 特性 | 说明 |
|------|------|
| **非侵入式** | 不改动 xfrpc 二进制与协议，仅作为外部进程生成配置并拉起 xfrpc 子进程 |
| **自动会话管理** | 加入 → 会话 → 状态上报 → 失败按指数退避重连，全程无人值守 |
| **动态域名映射** | 每台设备在 frps 上获得随会话轮换的动态子域名，地址随 session 漂移，防地址被长期锁定（防探测） |
| **集中用户鉴权** | 内嵌 auth server，配合 `frps_helper` 为 OpenWrt 提供统一登录鉴权，管理密码集中托管 |
| **安全密码轮换** | 自动生成并一次性轮换设备 root 密码，RSA-OAEP 加密落盘 |
| **设备唯一身份** | `device_id` = BASE62 UUID + 本机 MAC 后缀，贯穿 join/status/auth 全流程 |
| **轻量依赖** | 运行时只需 libevent2 / libcurl / json-c / OpenSSL，不依赖 libuci/libyaml |
| **自适应重连** | 指数退避 + 抖动，避免大量设备同时重试冲击服务器 |

---

## 三、系统构成

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
│   └─ nginx :8765 : 反代 LuCI + auth_request 集中鉴权          │
│                                                              │
│   xfrpc : 隧道客户端（外部二进制，xfrpc5 提供）                │
│   LuCI  : uhttpd :8000（OpenWrt Web UI）                     │
└──────────────────────────────────────────────────────────────┘
```

### 端口速查

| 端口 | 组件 | 地址 | 方向 |
|------|------|------|------|
| 8888 | auth server | 127.0.0.1 | 仅本机 |
| 8765 | nginx (LuCI 反代) | 0.0.0.0 | 本机对外 |
| 8000 | LuCI (uhttpd) | 0.0.0.0 | 本机 |
| 6999 | frps_helper 管理/认证 | 云端 | 对外 |
| 7000 | xfrpc 服务端 (frps) | 云端 | 对外 |

> auth server 仅监听 `127.0.0.1`，外部不可直连，必须经 nginx `auth_request` 触发认证。

---

## 四、快速开始

### 4.1 前置条件

- OpenWrt 设备上已部署 **xfrpc 5.x**（`/usr/bin/xfrpc`），可下载 `monkfish-iot/xfrpc5` 的预编译包。
- 云端 `frps_helper` 已运行（管理接口 + 认证接口 + frps）。
- 设备可访问管理服务器地址。

### 4.2 在 OpenWrt 源码树中构建

将本仓库放入 OpenWrt 源码树并启用：

```sh
cp -r xfrpc_loader openwrt/package/xfrpc_loader/
cd openwrt
make menuconfig          # Network 下启用 xfrpc_loader
make -j$(nproc) V=s package/xfrpc_loader/compile
```

可选构建参数：

```sh
LOCAL_SKEY=1             # 默认：使用本地 OpenSSL 密钥（device_id 存 /etc/config/skey/）
LOCAL_SKEY=0             # 使用厂商 libskey
INSTALL_PASSWD_SH=0      # 不安装 show_luci_passwd.sh
```

### 4.3 安装到设备

```sh
scp packages/*/xfrpc_loader_*.ipk root@<设备IP>:/tmp/
opkg install /tmp/xfrpc_loader_*.ipk
opkg install libevent2 libcurl libjson-c libopenssl
```

### 4.4 最小配置

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

### 4.5 启用集中鉴权（配合 frps_helper）

```sh
uci set xfrpc_loader.auth.enabled='1'
uci set xfrpc_loader.auth.remote_host='auth.example.com'
uci set xfrpc_loader.auth.remote_port='6999'
uci set xfrpc_loader.auth.remote_path='/api/v1/auth'
uci commit xfrpc_loader
/etc/init.d/xfrpc_loader restart
```

启用后，远程用户通过 nginx:8765 访问 LuCI，认证由 `frps_helper` 集中校验并下发 token，`xfrpc_loader` 用该 token 换取 LuCI `sysauth` Cookie 实施登录。

---

## 五、配置说明

完整配置见 `files/xfrpc_loader.uci` 与源码内 `src/xfrpc_loader.json.example`。关键项：

| 段 | 字段 | 默认 | 说明 |
|----|------|------|------|
| main | `server_name` / `server_ip` | 空 | 管理服务器，至少一个非空 |
| main | `server_port` | 6999 | 管理服务器端口 |
| main | `protocol` | https | `http` / `https` |
| main | `local_if` | br-lan | 本机接口（取 MAC/IP） |
| auth | `enabled` | 0 | 是否启用集中鉴权服务 |
| auth | `remote_*` | — | 远程认证服务器地址与路径 |
| auth | `modify_local_password` | 0 | 关闭时用默认账号密码锁用户；开启时随机轮换本机密码 |

---

## 六、文档

| 文档 | 位置 |
|------|------|
| 使用说明 | `docs/cn/使用说明.md` |
| 设计文档 | `docs/cn/设计文档.md` |
| 管理服务器 API（客户端适配） | `docs/cn/客户端适配规范.md` |
| 认证服务器接口规范 | `docs/cn/认证服务器接口规范.md` |
| nginx 登录调用文档 | `docs/cn/nginx登录调用文档.md` |

---

## 七、安全说明

- auth server 仅监听本机回环地址，外部不可直连。
- 设备 root 密码加密落盘（RSA），文件外泄无法直接用。
- 设备动态域名随会话轮换，防止地址被长期锁定（防探测）。
- HTTPS 证书校验默认由 OpenWrt curl 决定，生产环境建议配置受信任证书。

---

## 八、许可与致谢

- 采用 Apache-2.0 开源许可证，见 `LICENSE`。
- 第三方依赖与致谢见 `NOTICE`。

更多信息请访问：`https://github.com/monkfish-iot/xfrpc_loader`