/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Monkfish
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef XFRPC_LOADER_AUTH_LOCAL_H
#define XFRPC_LOADER_AUTH_LOCAL_H

#include <time.h>
#include <stddef.h>

/*
 * 默认 LuCI 密码（root 空密码）。
 * 首次使用（localpasswd 文件不存在）时用此密码登录 LuCI。
 * 以后要换密码时修改此常量。
 */
#define DEFAULT_LUCI_PASSWORD	""

/* 加密后的 LuCI 密码文件（skey 公钥加密，Base64 存储） */
#define LOCALPASSWD_FILE	"/etc/config/localpasswd"

/*
 * UBUS 会话凭据（ubus session.login 返回的 ubus_rpc_session）。
 * 结构名沿用历史命名 luci_token_t，对 WrtHub-UI 输出的 JSON 字段名
 * "luci_token" 也保留（契约不变），实际值是 ubus rpc_session。
 */
typedef struct {
	char	token[256];	/* ubus_rpc_session 字符串 */
	time_t	obtained_at;	/* 获取时间 */
	int	expires;	/* 有效期(秒)，rpcd 默认 300 */
	int	valid;		/* 是否有效 */
} luci_token_t;

/*
 * auth_local_get_password_ex 的密码来源/失败原因码：
 *   AUTH_LPWD_OK           成功解密 localpasswd（或回退默认密码，见下）
 *   AUTH_LPWD_NOT_INIT     localpasswd 不存在（设备未初始化），回退空密码
 *   AUTH_LPWD_DECRYPT_FAIL localpasswd 存在但解密失败（公私钥不匹配/
 *                          文件损坏），回退空密码
 */
enum {
	AUTH_LPWD_OK = 0,
	AUTH_LPWD_NOT_INIT = 1,
	AUTH_LPWD_DECRYPT_FAIL = 2,
};

/*
 * 获取 LuCI 密码：
 *   - 如果 /etc/config/localpasswd 存在，读取并用 skey 私钥解密
 *   - 如果不存在，使用 DEFAULT_LUCI_PASSWORD（root 空密码）
 *   password 输出明文密码（调用方提供 >= 32 字节缓冲区）
 *   reason 可为 NULL；非 NULL 时输出 AUTH_LPWD_* 原因码，
 *   供调用方向运维侧区分"未初始化"与"解密失败"。
 *   返回 0 成功，-1 失败。
 */
int auth_local_get_password_ex(char *password, size_t pwd_sz, int *reason);

/* 兼容包装：不关心失败原因时使用 */
int auth_local_get_password(char *password, size_t pwd_sz);

/*
 * 轮换 LuCI 密码：
 *   - 生成 16 字符随机密码
 *   - 用 skey 公钥加密后保存到 /etc/config/localpasswd
 *   - 通过 passwd 修改 root 密码为新密码
 *   new_password 输出新密码（调用方提供 >= 32 字节缓冲区，可为 NULL）
 *   返回 0 成功，-1 失败。
 */
int auth_local_rotate_password(char *new_password, size_t pwd_sz);

/*
 * 使用指定用户名/明文密码设置登录凭证（原子操作）：
 *   - 通过 passwd 将指定用户的系统密码设为明文密码
 *   - 用 skey 公钥加密后写入 /etc/config/localpasswd
 * 原子性保证与轮换一致：先改系统密码、成功后落盘，落盘失败回滚。
 * 用于"修改本机密码"开关关闭时，用配置默认用户名/密码锁死用户。
 * 返回 0 成功，-1 失败。
 */
int auth_local_set_password(const char *username, const char *password);

/*
 * 通过 UBUS JSON-RPC session.login 登录设备 rpcd，获取 ubus_rpc_session。
 * 设备 OpenWrt 已卸载所有 LuCI 模块，不再走 /cgi-bin/luci/rpc/auth。
 *   password 为 root 账号的密码
 *   返回 0 成功，-1 失败。
 */
int auth_local_ubus_login(const char *password, luci_token_t *token);

#endif /* XFRPC_LOADER_AUTH_LOCAL_H */
