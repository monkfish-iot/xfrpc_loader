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
#ifndef XFRPC_LOADER_AUTH_SERVER_H
#define XFRPC_LOADER_AUTH_SERVER_H

#include <event2/event.h>
#include <event2/http.h>
#include "config.h"
#include "device_info.h"
#include "session.h"

/*
 * 认证服务器上下文
 *   在 INIT 之后启动（只要配置启用就监听端口），TERM 时停止。
 *   RUNNING 之前返回 503（session 未就绪），RUNNING 后正常认证。
 *
 * 新逻辑（面向用户输入）：
 *   1. 接收用户输入的用户名/密码（GET Basic auth 或 POST JSON body）
 *   2. 补齐 device_id / mac / session_id，发往远程认证服务器
 *   3. 远程通过 → 读取 /etc/config/localpasswd 解密得到 LuCI 密码
 *      （文件不存在则用默认空密码）
 *   4. 用 root + 该密码登录 LuCI RPC，获取 session token
 *   5. 登录成功后生成 16 字符随机密码，用 skey 公钥加密保存到
 *      /etc/config/localpasswd（密码轮换）
 *   6. 返回远程 token + LuCI token + 用户信息给 nginx
 *
 *   密码按需获取，无需缓存；每次认证都重新登录 LuCI 并轮换密码。
 */
typedef struct {
	struct event_base	*base;
	struct evhttp		*http;
	int			server_ready;	/* evhttp 是否已绑定端口 */
	const xfrpc_config_t	*cfg;
	const device_info_t	*dev;
	const session_info_t	*sess;
} auth_server_ctx_t;

/*
 * 初始化认证服务器上下文（不启动 evhttp）。
 *   在 sm_init 之后、INIT 状态进入前调用。
 *   只初始化 cfg/dev/sess 指针，不绑定端口。
 */
void auth_server_init_ctx(auth_server_ctx_t *ctx,
			  struct event_base *base,
			  const xfrpc_config_t *cfg,
			  const device_info_t *dev,
			  const session_info_t *sess);

/*
 * 启动认证服务器（绑定端口）。
 *   配置启用时在 init_enter 末尾调用，RUNNING 状态之前已可监听端口。
 *   未 join 时请求返回 503，避免 nginx 连接拒绝。
 *   返回 0：服务器启动成功
 *   返回 -1：evhttp 绑定失败
 */
int auth_server_start(auth_server_ctx_t *ctx);

/*
 * 停止认证服务器。
 *   在 term_enter 中调用，释放 evhttp 资源。
 */
void auth_server_stop(auth_server_ctx_t *ctx);

#endif /* XFRPC_LOADER_AUTH_SERVER_H */
