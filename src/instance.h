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
#include "control_server.h"

#include <sys/types.h>
#include <signal.h>		/* sig_atomic_t */
#include <event2/event.h>

/*
 * 终止信号（SIGINT/SIGTERM）请求标志。
 *
 * join/status/auth 等流程在 libevent 回调栈中同步执行 libcurl，单次最长
 * 阻塞 join_timeout（默认 10s）。该窗口内事件循环被占住，SIGINT/SIGTERM
 * 即使被内核投递也无法及时派发。信号处理函数直接置位此标志，curl 的
 * 进度回调轮询到后立即中止传输，使进程在约 1 秒内响应 Ctrl+C。
 */
extern volatile sig_atomic_t g_terminate_requested;

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
    struct event	*ev_sig;	/* SIGINT/SIGTERM self-pipe 读事件 */
    int			sig_pipe[2];	/* [0]=读 [1]=写（信号处理函数写入） */
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

    /* ---- webauthd 控制面（webauthd-control/v1） ---- */
    control_server_ctx_t	control;
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
