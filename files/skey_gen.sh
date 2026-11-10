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
# skey_gen.sh - 生成本地密钥文件（手工/调试工具，不随 ipk 安装）
#
# 注意：xfrpc_loader（LOCAL_SKEY 模式）已内置等价的密钥生成逻辑，
# 首次启动时由进程内 libcrypto 直接生成，无需 openssl 命令行，
# 也不依赖本脚本。本脚本仅保留用于手工重置/调试（需自行安装
# openssl-util 提供 openssl 命令）。
#
# 在 /etc/config/skey/ 目录下生成：
#   - private_key.pem  RSA-2048 私钥
#   - public_key.pem   RSA-2048 公钥
#   - device_id         UUID V4 的 BASE62 编码（22 字符）
#
# 如果文件已存在则跳过，不重复生成。

set -e

# openssl 命令行由 openssl-util 包提供（libopenssl 仅含共享库，不含 CLI）；
# 缺失时明确报错退出，避免裸 "openssl: not found"（rc=127）难以排查
if ! command -v openssl >/dev/null 2>&1; then
    echo "skey_gen.sh: openssl command not found - install 'openssl-util' package" >&2
    exit 1
fi

SKEY_DIR="/etc/config/skey"

# 创建目录
mkdir -p "$SKEY_DIR"

# ---- 生成 RSA-2048 密钥对 ----

if [ ! -f "$SKEY_DIR/private_key.pem" ]; then
    openssl genrsa -out "$SKEY_DIR/private_key.pem" 2048
    chmod 600 "$SKEY_DIR/private_key.pem"
fi

if [ ! -f "$SKEY_DIR/public_key.pem" ]; then
    openssl rsa -in "$SKEY_DIR/private_key.pem" \
        -pubout -out "$SKEY_DIR/public_key.pem"
fi

# ---- 生成 device_id ----
# UUID V4 -> 16 字节二进制 -> BASE62 编码 -> 22 字符

if [ ! -f "$SKEY_DIR/device_id" ]; then
    UUID=$(cat /proc/sys/kernel/random/uuid)
    # 去掉横杠，得到 32 字符 hex 串
    HEX=$(echo "$UUID" | tr -d '-')

    # 用 awk 做 BASE62 编码（长除法）
    DEVICE_ID=$(awk -v hex="$HEX" 'BEGIN {
        b62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

        # hex 字符串转 16 字节数组（大端）
        n = length(hex) / 2
        for (i = 0; i < 16; i++) {
            if (i < n) {
                hi = tolower(substr(hex, i * 2 + 1, 1))
                lo = tolower(substr(hex, i * 2 + 2, 1))
                h = "0123456789abcdef"
                num[i] = (index(h, hi) - 1) * 16 + (index(h, lo) - 1)
            } else {
                num[i] = 0
            }
        }

        # 长除法：num /= 62，每次取余数
        result = ""
        for (;;) {
            rem = 0
            all_zero = 1
            for (i = 0; i < 16; i++) {
                cur = rem * 256 + num[i]
                num[i] = int(cur / 62)
                rem = cur - num[i] * 62
                if (num[i] != 0)
                    all_zero = 0
            }
            result = result substr(b62, rem + 1, 1)
            if (all_zero)
                break
        }

        # 补零到 22 字符
        while (length(result) < 22)
            result = result "0"

        # 翻转（长除法从低位到高位，需要反转）
        final = ""
        for (i = length(result); i >= 1; i--)
            final = final substr(result, i, 1)

        print final
    }')

    echo "$DEVICE_ID" > "$SKEY_DIR/device_id"
fi
