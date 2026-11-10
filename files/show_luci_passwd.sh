#!/bin/sh
#
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Monkfish
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# show_luci_passwd.sh - 显示当前 LuCI root 明文密码
#
# 通过 xfrpc_loader 本地认证服务(127.0.0.1) 的 /api/password 接口获取，
# 由服务端 C 代码负责 RSA 解密（避免 shell 依赖 openssl 命令行）。
#
# 用法：
#   show_luci_passwd.sh            # 输出明文密码
#   show_luci_passwd.sh -q         # 静默模式（出错时不打印错误信息）
#
# 依赖：curl（OpenWrt 上需安装 curl 包）

set -u

AUTH_BASE="http://127.0.0.1:${AUTH_PORT:-8888}"

QUIET=0
[ "${1:-}" = "-q" ] && QUIET=1

log_err() {
	[ "$QUIET" -eq 1 ] || echo "show_luci_passwd: $*" >&2
}

# 1. 检查 curl
if ! command -v curl >/dev/null 2>&1; then
	log_err "curl not found (install curl)"
	exit 1
fi

# 2. 调用认证服务接口获取明文密码
RESP=$(curl -fsS --connect-timeout 5 -m 10 \
	"${AUTH_BASE}/api/password" 2>/dev/null) || {
	log_err "failed to query ${AUTH_BASE}/api/password (is xfrpc_loader running?)"
	exit 1
}

# 3. 解析 JSON 中的 password 字段（busybox 无 jq，用 sed 提取）
PASSWORD=$(echo "$RESP" | sed -n 's/.*"password":"\([^"]*\)".*/\1/p')

if [ -z "$PASSWORD" ]; then
	log_err "no password in response: $RESP"
	log_err "device not initialized yet (use default root password)"
	exit 1
fi

# 4. 输出明文密码
echo "$PASSWORD"
exit 0
