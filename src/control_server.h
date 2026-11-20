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
#ifndef XFRPC_LOADER_CONTROL_SERVER_H
#define XFRPC_LOADER_CONTROL_SERVER_H

#include <event2/event.h>
#include <event2/listener.h>
#include <stdint.h>
#include <time.h>

/* webauthd 主动连接的本机控制通道（webauthd-control/v1） */
#define CONTROL_SOCKET_DIR	"/var/run/xfrpc_loader"
#define CONTROL_SOCKET_PATH	"/var/run/xfrpc_loader/webauthd-control.sock"

struct inst_t;

typedef struct {
	struct evconnlistener	*listener;
	struct inst_t		*inst;

	/*
	 * generation 只在期望状态内容变化时递增。
	 * last_body 保存不含 generation 的规范化 JSON，用于比较。
	 */
	uint64_t		generation;
	char			*last_body;

	/* 最近一次 ACK，仅用于日志和排障 */
	uint64_t		last_ack_generation;
	char			last_ack_status[32];
	int			last_ack_error;
	time_t			last_ack_time;

	/* 冷字段重启节流 */
	time_t			last_restart_time;
} control_server_ctx_t;

/*
 * 启动控制服务端。失败返回 -1，调用方按非致命处理。
 * inst 必须在整个生命周期内有效。
 */
int control_server_start(control_server_ctx_t *srv, struct event_base *base,
			 struct inst_t *inst);

/* 停止监听并释放资源。 */
void control_server_stop(control_server_ctx_t *srv);

#endif /* XFRPC_LOADER_CONTROL_SERVER_H */
