# xfrpc_loader

English | [简体中文](README.zh-CN.md)

A **non-invasive** external helper daemon for the **xfrpc** (FRP client) on
OpenWrt. It onboards devices to the Monkfish cloud management platform —
securely and **en masse** — with centralized management, authentication, and
secure remote access to each device's web UI through an FRP tunnel.

> - Language: C (C11) · Platform: OpenWrt · License: Apache-2.0
> - Requires: **xfrpc 5.x or later**
> - Prebuilt xfrpc client package: <https://github.com/monkfish-iot/xfrpc5>
> - Companion server: `frps_helper` (same organization)
> - **Project documentation site: <http://monkfish.cn>**

---

## The Problem It Solves

When you manage many distributed OpenWrt routers remotely, doing it manually —
configuring frp one by one, assigning fixed addresses, and maintaining a
separate admin password per device — is tedious and insecure.

`xfrpc_loader` automates this as an **external helper** (without modifying
xfrpc itself):

1. **Automatic onboarding** — on boot, the device issues a signed "join
   request" to the management server, establishes a session, generates
   `xfrpc.ini`, and launches the xfrpc subprocess to connect to frps.
2. **Batch management** — devices (MAC / device_id) are centrally registered
   server-side for unified authorization and disabling.
3. **Dynamic domains** — each device gets a session-rotating dynamic subdomain
   on frps, so remote users reach it by hostname without remembering IPs.
4. **Centrally managed passwords** — together with `frps_helper`, it provides
   centralized user authentication for the devices' Web login, holding the
   scattered per-device admin passwords safely in one place.

In short: **lightweight and zero-modification on the device; centralized,
secure, and scalable on the management side.**

## Key Features

| Feature | Description |
|---------|-------------|
| **Non-invasive** | Does not touch the xfrpc binary or protocol; only generates config and launches the xfrpc subprocess. |
| **Mutual authentication** | Signature-based join: public-key pinning on the device side, root-CA-verified server certificate chain, nonce + timestamp binding (anti-registration-squatting, anti-replay). |
| **Automatic sessions** | Join → session → status reporting → exponential-backoff reconnect, all unattended. |
| **Dynamic domain mapping** | Each device's subdomain rotates with the session ID, preventing long-term address fingerprinting (anti-probing). |
| **Tunnel / direct dual mode** | The server assigns `frpc_mode` in the join response: `1` (default) starts xfrpc (tunnel mode); `0` skips xfrpc and keeps status keepalive only, exposing LuCI for direct access via `http://<local_if_IP>:8765`. |
| **Centralized auth** | Embedded auth server (127.0.0.1:8888) works with nginx `auth_request` and `frps_helper` for unified Web login auth. |
| **Secure password rotation** | Optionally rotates the local LuCI root password after each login, stored RSA-encrypted on disk. |
| **Control channel** | Unix socket (`webauthd-control/v1`) pushing desired state (Portal URL, RADIUS parameters, tenant ID) to `webauthd` with generation/lease-based ACK. |
| **Time sync** | Server-pushed clock and timezone synchronization on join/status responses. |
| **Lightweight deps** | Runtime needs only libevent2 / libcurl / json-c / OpenSSL; no libuci/libyaml. |

## Architecture

```
┌──────────────────────────── Cloud ────────────────────────────┐
│                                                               │
│   frps_helper (management + auth server)                      │
│   ├─ Management    :6999  (join / status)                     │
│   ├─ Remote auth   :6999  (/api/v1/auth)                      │
│   └─ frps          :7000  (receives xfrpc tunnels)            │
│   (not in this repo — see the frps_helper repository)         │
└──────────────────────────────┬────────────────────────────────┘
                               │ xfrpc tunnel / local DNS
                               ▼
┌────────────────────────── OpenWrt device ─────────────────────┐
│                                                               │
│   xfrpc_loader (this repo)                                    │
│   ├─ Main daemon  : join / session / status                   │
│   ├─ xfrpc mgr    : generate ini + launch xfrpc subprocess    │
│   ├─ auth server  :8888 (127.0.0.1 only)                      │
│   ├─ control sock : webauthd-control/v1 (to webauthd)         │
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
| 8765 | nginx (mgmt reverse proxy) | per `frpc_mode` | tunnel mode 127.0.0.1 / direct mode any |
| 8000 | LuCI (uhttpd) | 0.0.0.0 | local |
| 6999 | frps_helper mgmt/auth | cloud | public |
| 7000 | xfrpc server (frps) | cloud | public |

> The auth server listens only on `127.0.0.1`; it is never externally
> reachable and must be triggered through nginx `auth_request`. The 8765
> vhost also blocks direct access to the LuCI RPC login and password-change
> endpoints. Bind-address templates for tunnel/direct mode live in
> `src/conf/`.

## How It Works

The daemon is event-driven (libevent2) and organized around a finite state
machine:

```
INIT --> JOINING --> RUNNING --> REJOIN --> JOINING
  |         |          |                     (retry with
  v         v          v                      backoff)
 TERM <-----+----------+-------- (SIGTERM/SIGINT)
```

1. **INIT** — Load configuration (`/tmp/xfrpc_loader.json`, rendered from UCI
   by the init script), collect device info, start the auth service.
2. **JOINING** — Send a signed join request to the cloud server. On success
   the server returns a session ID, the xfrpc server address, an optional
   server certificate chain, and optional RADIUS/Portal parameters.
3. **RUNNING** — Spawn `xfrpc` with the generated INI, report status
   periodically, apply server-pushed timezone, and serve local auth requests.
4. **REJOIN** — On status failure or `xfrpc` exit, tear down the tunnel and
   rejoin with exponential backoff.
5. **TERM** — Stop `xfrpc`, the auth service, and the control channel, then
   exit cleanly.

## Getting Started

### Prerequisites

- **xfrpc 5.x** deployed on the device (`/usr/bin/xfrpc`), e.g. from the
  prebuilt [monkfish-iot/xfrpc5](https://github.com/monkfish-iot/xfrpc5)
  packages.
- `frps_helper` running in the cloud (management + auth + frps).
- The device can reach the management server address.

### Build as an OpenWrt Package

Copy this repository into your OpenWrt SDK/source tree, then:

```sh
cp -r xfrpc_loader openwrt/package/xfrpc_loader/
cd openwrt
make menuconfig          # enable xfrpc_loader under "Monkfish Softwares"
make -j$(nproc) V=s package/xfrpc_loader/compile
```

The resulting `xfrpc_loader_<version>_<arch>.ipk` can be installed with
`opkg install`.

Build-time options (edit the top of `Makefile`):

| Variable           | Default | Meaning |
|--------------------|---------|---------|
| `LOCAL_SKEY`       | `1`     | `1`: keys self-generated by libcrypto on first boot (stored in `/etc/config/skey/`), depends on `openssl-util`. `0`: use the `libskey` static library with factory-provisioned material in `/etc/skey/` (scheme-D public-key pinning mutual authentication; requires the root CA `/etc/skey/ca.pem` shipped with the firmware). |
| `INSTALL_PASSWD_SH`| `0`     | `1`: also install `show_luci_passwd.sh`, a helper that prints the current LuCI plaintext password via the local auth service. |

### Standalone Build (development)

```sh
cd src
make          # produces ./xfrpc_loader
make clean
```

Requires development headers for libevent2, libcurl, json-c, libskey and
OpenSSL on the host.

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

Once enabled, remote users access LuCI via nginx:8765; `frps_helper` validates
their credentials and issues a token, and `xfrpc_loader` exchanges that token
for a LuCI `sysauth` cookie to sign in.

## Repository Layout

```
Makefile                     OpenWrt package Makefile (build entry)
files/
  xfrpc_loader.uci           Default UCI config (/etc/config/xfrpc_loader)
  xfrpc_loader.init          procd init script (/etc/init.d/xfrpc_loader)
  etc/nginx/conf.d/ubus.conf nginx vhost for the ubus/LuCI tunnel entry
  etc/uci-defaults/          sysupgrade keep-file script (libskey mode)
  skey_gen.sh                Manual/debug key generation tool (not installed)
  show_luci_passwd.sh        Print current LuCI plaintext password (optional)
src/                         C source code of the daemon
  Makefile                   Standalone host build (for development)
  conf/                      nginx vhost templates (tunnel / direct mode)
  LICENSE                    Apache License 2.0
  NOTICE                     Third-party attributions
```

## Configuration Reference

Configuration is managed via UCI (`/etc/config/xfrpc_loader`); the init
script renders it into `/tmp/xfrpc_loader.json` for the daemon.

### `main` section

| Option               | Default     | Description |
|----------------------|-------------|-------------|
| `server_name`        | *(empty)*   | Cloud server domain (takes precedence over IP; at least one of name/IP required) |
| `server_ip`          | `127.0.0.1` | Cloud server IP |
| `server_port`        | `6999`      | Cloud server port |
| `protocol`           | `https`     | `http` / `https` |
| `local_if`           | `br-lan`    | Local interface used for device info (MAC/IP) |
| `join_timeout`       | `10`        | Join request timeout (s) |
| `status_interval`    | `60`        | Status report interval (s) |
| `retry_interval`     | `5`         | Initial retry interval (s) |
| `max_retry_interval` | `300`       | Exponential backoff cap (s) |
| `max_join_retries`   | `0`         | Max join retries, `0` = unlimited |
| `time_sync_enabled`  | `1`         | Sync clock/timezone from server |
| `time_sync_threshold`| `5`         | Min clock skew (s) to trigger sync |

### `auth` section (centralized Web login auth)

| Option                  | Default        | Description |
|-------------------------|----------------|-------------|
| `enabled`               | `1`            | Enable the local auth service |
| `listen_port`           | `8888`         | Local listen port (loopback) |
| `remote_proto`          | `https`        | Remote auth protocol |
| `remote_host`           | *(empty)*      | Remote auth host (falls back to `server_name`) |
| `remote_port`           | `0`            | Remote auth port (falls back to `server_port`) |
| `remote_path`           | `/api/v1/auth` | Remote auth API path |
| `remote_timeout`        | `10`           | Remote auth timeout (s) |
| `token_cache_ttl`       | `240`          | Token cache TTL (s) |
| `token_retry_interval`  | `5`            | Token retry interval (s) |
| `modify_local_password` | `0`            | `0`: lock user with default account; `1`: rotate local LuCI password after login |
| `default_username`      | `root`         | Local login username |
| `default_password`      | `admin`        | Fallback local password |

Manage the service with:

```sh
/etc/init.d/xfrpc_loader start|stop|restart
logread -e xfrpc_loader
```

## Security Notes

- The auth server binds only to the loopback interface; it is never
  externally reachable.
- The device root password is stored RSA-encrypted; exfiltration of the file
  alone is not usable.
- The dynamic domain rotates with the session, preventing long-term address
  fingerprinting.
- HTTPS certificate verification is controlled by OpenWrt's curl; use
  trusted certificates in production.

## Documentation & Related Repositories

- **Project documentation site: <http://monkfish.cn>** — architecture,
  quickstart, server deployment, and interface specifications.
- [monkfish-iot/xfrpc5](https://github.com/monkfish-iot/xfrpc5) — prebuilt
  xfrpc client packages (5.x required).
- `frps_helper` — companion cloud-side management + authentication server
  (same organization).

## Runtime Dependencies

`libevent2`, `libcurl`, `libjson-c`, `libopenssl`, plus
`openssl-util` (default `LOCAL_SKEY=1` mode) or `skey`
(`LOCAL_SKEY=0` mode). At runtime the `xfrpc` binary must be present, and
nginx is used as the tunnel entry reverse proxy when installed.

## License

Copyright 2026 Monkfish. Licensed under the
[Apache License, Version 2.0](src/LICENSE).
Third-party component attributions are listed in [src/NOTICE](src/NOTICE).
