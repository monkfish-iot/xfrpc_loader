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
#ifndef XFRPC_LOADER_STATE_MACHINE_H
#define XFRPC_LOADER_STATE_MACHINE_H

#include <time.h>
#include <sys/types.h>
#include <event2/event.h>

#include "config.h"
#include "device_info.h"
#include "session.h"
#include "auth_server.h"

/* 前向声明：inst_t 在 instance.h 中定义 */
typedef struct inst_t inst_t;

typedef enum {
	ST_INIT = 0,
	ST_JOINING,
	ST_RUNNING,
	ST_REJOIN,
	ST_TERM,
	ST_MAX
} state_t;

typedef enum {
	EV_CFG_LOADED = 0,	/* 配置加载完成 */
	EV_CFG_FAILED,		/* 配置加载失败 */
	EV_JOIN_OK,		/* 加入成功 */
	EV_JOIN_FAIL,		/* 加入失败（可重试：网络错误、-1004/-2001） */
	EV_JOIN_REJECTED,	/* 加入被服务端拒绝（-1001/-1002），退避后重试 */
	EV_JOIN_TIMEOUT,	/* 加入超时 */
	EV_STATUS_OK,		/* 状态上报成功 */
	EV_STATUS_FAIL,		/* 状态上报失败 */
	EV_STATUS_TIMEOUT,	/* 状态上报超时 */
	EV_RETRY_EXPIRED,	/* 重试等待结束 */
	EV_XFRPC_EXITED,	/* xfrpc 子进程退出 */
	EV_SIGTERM,		/* 收到退出信号 */
	EV_MAX
} sm_event_t;

/* 单个状态的回调集合 */
typedef struct {
	void (*enter)(inst_t *inst);			/* 进入状态 */
	void (*exit) (inst_t *inst);			/* 离开状态 */
	void (*event)(inst_t *inst, sm_event_t ev,	/* 事件处理 */
		      void *data);
} state_callbacks_t;

/* 初始化状态机（注册回调表，创建定时器，初始化 auth 上下文） */
void sm_init(inst_t *inst);

/* 状态迁移：先 exit 旧状态，再 enter 新状态 */
void sm_transition(inst_t *inst, state_t next);

/* 事件分发：交给当前状态的 event 回调 */
void sm_dispatch(inst_t *inst, sm_event_t ev, void *data);

/* 状态名称（用于日志） */
const char *state_name(state_t s);

#endif /* XFRPC_LOADER_STATE_MACHINE_H */
