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
#include "session.h"

#include <stdio.h>
#include <string.h>

void session_set(session_info_t *s, const join_response_t *r)
{
	snprintf(s->session_id, sizeof(s->session_id), "%s",
		 r->session_id);
	snprintf(s->xfrpc_server_addr, sizeof(s->xfrpc_server_addr), "%s",
		 r->xfrpc_server_addr);

	s->xfrpc_server_port = r->xfrpc_server_port;
	s->frpc_mode = r->frpc_mode;
	snprintf(s->server_cert, sizeof(s->server_cert), "%s",
		 r->server_cert);
	s->valid = 1;

	/* 云端 RADIUS 对接参数（可选）：未下发时保持空/0，
	 * 消费方按字段存在性跳过 */
	snprintf(s->radius_auth_server, sizeof(s->radius_auth_server), "%s",
		 r->radius_auth_server);
	snprintf(s->radius_acct_server, sizeof(s->radius_acct_server), "%s",
		 r->radius_acct_server);
	snprintf(s->radius_nas_ip, sizeof(s->radius_nas_ip), "%s",
		 r->radius_nas_ip);
	snprintf(s->radius_auth_secret, sizeof(s->radius_auth_secret), "%s",
		 r->radius_auth_secret);
	snprintf(s->radius_acct_secret, sizeof(s->radius_acct_secret), "%s",
		 r->radius_acct_secret);
	s->radius_auth_port = r->radius_auth_port;
	s->radius_acct_port = r->radius_acct_port;
	snprintf(s->tenant_org_id, sizeof(s->tenant_org_id), "%s",
		 r->tenant_org_id);
}

void session_invalidate(session_info_t *s)
{
	memset(s, 0, sizeof(*s));
	s->valid = 0;
}
