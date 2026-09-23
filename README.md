# xfrpc_loader

**English** / **[中文](README_zh.md)**

A **non-invasive** external helper for the **xfrpc** client. It helps you securely and **en masse** onboard OpenWrt devices to frps servers, with centralized cloud-side management and authentication.

> - Language: C (C11)
> - Platform: OpenWrt
> - License: Apache-2.0
> - Requires: **xfrpc 5.x or later**
> - Prebuilt client package: `https://github.com/monkfish-iot/xfrpc5`
> - Companion server: `frps_helper` (see the same org)

---

## The Problem It Solves

When you manage many distributed OpenWrt routers remotely, doing it manually — configuring frp one by one, assigning fixed addresses, and maintaining separate admin passwords per device — is tedious and insecure.

`xfrpc_loader` does it automatically as an **external helper** (without modifying xfrpc itself):

1. **Automatic onboarding** — on boot, the device issues a "join request" to the management server, establishes a session, generates `xfrpc.ini`, and launches the xfrpc subprocess to connect to frps.
2. **Batch management** — devices (MAC / device_id) are centrally registered server-side for unified authorization and disabling.
3. **Dynamic domains** — each OpenWrt box gets a **dynamic domain** via the local DNS system on frps, so remote users reach it by hostname without remembering each device's IP.
4. **Centrally managed passwords** — together with `frps_helper`, xfrpc_loader provides **centralized user authentication** for HTTP/HTTPS web logins, safely holding the scattered device admin passwords in one place instead of hardcoding them on each device.

In short: **lightweight and zero-modification on the device; centralized, secure, and scalable on the management side.**

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Non-invasive** | Does not touch the xfrpc binary or protocol; only generates config and launches the xfrpc subprocess. |
| **Automatic sessions** | Join → session → status reporting → exponential-backoff reconnect, all unattended. |
| **Dynamic domain mapping** | Each device gets a session-rotating subdomain on frps; the address shifts with the session to prevent long-term fingerprinting (anti-probing). |
| **Centralized auth** | Embedded auth server works with `frps_helper` for unified login auth; admin passwords are centrally held. |
| **Secure password rotation** | Automatically generates and one-time-rotates the device root password, stored encrypted with RSA-OAEP. |
| **Unique device identity** | `device_id` = BASE62 UUID + local MAC suffix, used throughout join/status/auth. |
| **Lightweight deps** | Runtime needs only libevent2 / libcurl / json-c / OpenSSL; no libuci/libyaml. |
| **Adaptive reconnect** | Exponential backoff with jitter avoids hammering the server. |

---

## Architecture

```
┌──────────────────────────── Cloud ────────────────────────────┐
│                                                               │
│   frps_helper (management + auth server)                      │
│   ├─ Management    :6999  (join / status)                     │
│   ├─ Remote auth   :6999  (/api/v1/auth)                      │
│   └─ frps          :7000  (receives xfrpc tunnels)            │
│   (not in this repo — see the frps_helper repository)          │
└──────────────────────────────┬────────────────────────────────┘
                               │ xfrpc tunnel / local DNS
                               ▼
┌────────────────────────── OpenWrt device ─────────────────────┐
│                                                               │
│   xfrpc_loader (this repo)                                    │
│   ├─ Main daemon  : join / session / status                   │
│   ├─ xfrpc mgr    : generate ini + launch xfrpc subprocess    │
│   ├─ auth server  :8888 (127.0.0.1 only)                      │
│   └─ nginx :8765  : reverse proxy LuCI + auth_request auth    │
│                                                               │
│   xfrpc : tunnel client (external binary, from xfrpc5)        │
│   LuCI  : uhttpd :8000 (OpenWrt Web UI)                       │
└───────────────────────────────────────────────────────────────┘
```

### Ports at a Glance

| Port | Component | Bind | Direction |
|------|-----------|------|-----------|
| 8888 | auth server | 127.0.0.1 | loopback only |
| 8765 | nginx (LuCI proxy) | 0.0.0.0 | locally exposed |
| 8000 | LuCI (uhttpd) | 0.0.0.0 | local |
| 6999 | frps_helper mgmt/auth | cloud | public |
| 7000 | xfrpc server (frps) | cloud | public |

> The auth server listens only on `127.0.0.1`; it is not reachable externally and must be triggered through nginx `auth_request`.

---

## Getting Started

### Prerequisites

- **xfrpc 5.x** deployed on the device (`/usr/bin/xfrpc`), e.g. from `monkfish-iot/xfrpc5` prebuilt packages.
- `frps_helper` running in the cloud (management + auth + frps).
- The device can reach the management server address.

### Build in an OpenWrt Source Tree

```sh
cp -r xfrpc_loader openwrt/package/xfrpc_loader/
cd openwrt
make menuconfig              # enable xfrpc_loader under Network
make -j$(nproc) V=s package/xfrpc_loader/compile
```

Optional build flags:

```sh
LOCAL_SKEY=1                 # default: local OpenSSL keys (device_id in /etc/config/skey/)
LOCAL_SKEY=0                 # use vendor libskey
INSTALL_PASSWD_SH=0          # skip installing show_luci_passwd.sh
```

### Install on the Device

```sh
scp packages/*/xfrpc_loader_*.ipk root@<DEVICE_IP>:/tmp/
opkg install /tmp/xfrpc_loader_*.ipk
opkg install libevent2 libcurl libjson-c libopenssl
```

### Minimal Configuration

```sh
# Point to the management server (at least one of server_name / server_ip)
uci set xfrpc_loader.main.server_name='dm.example.com'
uci set xfrpc_loader.main.server_port='6999'
uci set xfrpc_loader.main.protocol='https'
uci commit xfrpc_loader

/etc/init.d/xfrpc_loader enable
/etc/init.d/xfrpc_loader start
```

Verify:

```sh
logread | grep xfrpc_loader | tail -30
# Expect: join ok, session=... ; xfrpc started, pid=...
```

### Enable Centralized Auth (with frps_helper)

```sh
uci set xfrpc_loader.auth.enabled='1'
uci set xfrpc_loader.auth.remote_host='auth.example.com'
uci set xfrpc_loader.auth.remote_port='6999'
uci set xfrpc_loader.auth.remote_path='/api/v1/auth'
uci commit xfrpc_loader
/etc/init.d/xfrpc_loader restart
```

Once enabled, remote users access LuCI via nginx:8765; `frps_helper` validates their credentials and issues a token, and `xfrpc_loader` exchanges that token for a LuCI `sysauth` cookie to sign in.

---

## Configuration

See `files/xfrpc_loader.uci` and the bundled `src/xfrpc_loader.json.example`. Key options:

| Section | Field | Default | Description |
|---------|-------|---------|-------------|
| main | `server_name` / `server_ip` | empty | Management server; at least one required |
| main | `server_port` | 6999 | Management server port |
| main | `protocol` | https | `http` / `https` |
| main | `local_if` | br-lan | Local interface (for MAC/IP) |
| auth | `enabled` | 0 | Enable centralized auth service |
| auth | `remote_*` | — | Remote auth server address & path |
| auth | `modify_local_password` | 0 | 0 = lock user with default account; 1 = rotate local password |

---

## Documentation

| Doc | Location |
|-----|----------|
| Usage guide | `docs/cn/使用说明.md` |
| Design doc | `docs/cn/设计文档.md` |
| Management API (client spec) | `docs/cn/客户端适配规范.md` |
| Auth server interface | `docs/cn/认证服务器接口规范.md` |
| nginx login doc | `docs/cn/nginx登录调用文档.md` |

---

## Security Notes

- The auth server binds only to the loopback interface; it is never externally reachable.
- The device root password is stored encrypted (RSA); exfiltration alone is not usable.
- The dynamic domain rotates with the session, preventing long-term address fingerprinting.
- HTTPS certificate verification is controlled by OpenWrt's curl; use trusted certs in production.

---

## License & Notices

- Licensed under Apache-2.0, see `LICENSE`.
- Third-party acknowledgments in `NOTICE`.

More info: `https://github.com/monkfish-iot/xfrpc_loader`