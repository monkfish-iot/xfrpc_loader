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
