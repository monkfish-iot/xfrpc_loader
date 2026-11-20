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
#ifndef XFRPC_LOADER_SESSION_H
#define XFRPC_LOADER_SESSION_H

#include "protocol.h"

typedef struct {
	int	valid;				/* 0=无效，1=有效 */
	char	session_id[128];			/* 服务器下发 */
	char	xfrpc_server_addr[64];		/* xfrpc 服务端地址 */
	int	xfrpc_server_port;		/* xfrpc 服务端端口 */
	int	frpc_mode;			/* 0=不启动 xfrpc，1=启动（缺省） */
	char	server_cert[SKEY_CERT_LEN];	/* 服务器证书链（join 双向认证时缓存，
						 * 用于 status/auth 验签） */

	/* 云端下发的 RADIUS 对接参数（join 响应 body.radius，全局信息）。
	 * 未下发时全部为空/0，消费方据此跳过；缓冲上限与
	 * local_config_http_api.md §4.2 的可写字段长度一致，
	 * JOIN 成功后经 webauthd 本地配置接口（127.0.0.1:60000）推送。 */
	char	radius_auth_server[24];		/* 主认证服务器地址 */
	char	radius_acct_server[24];		/* 主记账服务器地址 */
	char	radius_nas_ip[32];		/* NAS IP */
	char	radius_auth_secret[32];		/* 认证共享密钥 */
	char	radius_acct_secret[32];		/* 记账共享密钥 */
	int	radius_auth_port;		/* 认证端口 */
	int	radius_acct_port;		/* 记账端口 */
	char	tenant_org_id[64];		/* 租户 ID（join 响应 body.radius 可选下发） */
} session_info_t;

/* 从加入响应设置会话信息 */
void session_set(session_info_t *s, const join_response_t *r);

/* 使会话失效 */
void session_invalidate(session_info_t *s);

/* 会话是否有效 */
static inline int session_valid(const session_info_t *s)
{
	return s && s->valid && s->session_id[0];
}

#endif /* XFRPC_LOADER_SESSION_H */
