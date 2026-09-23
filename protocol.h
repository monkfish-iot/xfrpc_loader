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
#ifndef XFRPC_LOADER_PROTOCOL_H
#define XFRPC_LOADER_PROTOCOL_H

#include <stddef.h>

#include "device_info.h"
#include "system_status.h"

/* 加入成功响应解析结果 */
typedef struct {
	char	session_id[128];
	char	xfrpc_server_addr[64];
	int	xfrpc_server_port;
	char	ca_pub_key[1024];	/* 服务器 CA 公钥 PEM，可能为空 */
} join_response_t;

/*
 * 构造加入请求 JSON body。
 * 返回 malloc 分配的字符串，调用方负责 free。失败返回 NULL。
 */
char *protocol_build_join_request(const device_info_t *dev);

/*
 * 解析加入响应。
 * 返回 0 表示解析成功（不论 code 是否为 0）；
 * 返回 -1 表示 JSON 解析失败。
 * code 输出业务码；code == 0 时 resp 填充会话信息。
 */
int protocol_parse_join_response(const char *body, join_response_t *resp,
				 int *code, char *msg, size_t msg_sz);

/*
 * 构造状态请求 JSON body。
 * 返回 malloc 分配的字符串，调用方负责 free。失败返回 NULL。
 */
char *protocol_build_status_request(const system_status_t *st);

/*
 * 解析状态响应。
 * 返回 0 表示解析成功；返回 -1 表示 JSON 解析失败。
 * code 输出业务码。
 */
int protocol_parse_status_response(const char *body, int *code,
				   char *msg, size_t msg_sz);

#endif /* XFRPC_LOADER_PROTOCOL_H */
