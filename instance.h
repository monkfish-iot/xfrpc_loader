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
#ifndef XFRPC_LOADER_INSTANCE_H
#define XFRPC_LOADER_INSTANCE_H

#include "state_machine.h"	/* state_t, sm_event_t, state_callbacks_t, inst_t 前向声明 */

#include <sys/types.h>
#include <event2/event.h>

/*
 * 全局实例结构体（扁平化）
 *
 * 所有运行时上下文集中在此结构体中，通过指针传递给各模块。
 */
struct inst_t {
    /* ---- 命令行 / 进程信息 ---- */
    int		foreground;		/* 是否前台运行 */
    const char	*progname;		/* 程序名称，用于 usage */
    pid_t	pid;			/* 进程 PID */
    int		pid_fd;			/* PID 文件锁描述符（-1=未锁定） */

    /* ---- libevent2 核心 ---- */
    struct event_base	*base;		/* event 主循环 */
    struct event	*ev_term;	/* SIGTERM 信号事件 */
    struct event	*ev_int;	/* SIGINT 信号事件 */
    struct event	*ev_chld;	/* SIGCHLD 信号事件 */

    /* ---- 状态机 ---- */
    state_t			current;	/* 当前状态 */
    const state_callbacks_t	*cbs[ST_MAX];	/* 状态 → 回调表 */
    struct event		*status_timer;		/* 周期状态上报 (EV_PERSIST) */
    struct event		*retry_timer;		/* 重试等待 (一次性) */
    struct event		*xfrpc_restart_timer;	/* xfrpc 延迟重启 (一次性) */

    /* ---- 运行时上下文 ---- */
    xfrpc_config_t	cfg;
    device_info_t	dev;
    session_info_t	session;

    /* ---- xfrpc 子进程 ---- */
    pid_t	xfrpc_pid;
    int		xfrpc_restart_count;
    time_t	xfrpc_first_crash;

    /* ---- 加入重试计数 ---- */
    int		join_retry_count;

    /* ---- nginx 认证扩展 ---- */
    auth_server_ctx_t	auth;
};

/*
 * 初始化实例：解析命令行、初始化日志、加 PID 锁、
 * 初始化 libcurl/libevent、创建状态机和信号事件。
 * 返回 0 成功，-1 失败（失败时已清理资源）。
 */
int inst_init(inst_t *inst, int argc, char **argv);

/*
 * 清理实例：释放定时器、信号事件、event_base，
 * 解除 PID 锁、清理 libcurl、关闭日志。
 */
void inst_cleanup(inst_t *inst);

#endif /* XFRPC_LOADER_INSTANCE_H */
