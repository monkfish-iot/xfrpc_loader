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
#include "instance.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <curl/curl.h>

#define PID_FILE "/var/run/xfrpc_loader.pid"

/* ---- 信号回调 ---- */

static void on_sigterm_cb(evutil_socket_t fd, short what, void *arg)
{
	inst_t *inst = arg;

	(void)fd;
	(void)what;

	log_info("received termination signal");
	sm_dispatch(inst, EV_SIGTERM, NULL);
}

static void on_sigchld_cb(evutil_socket_t fd, short what, void *arg)
{
	inst_t *inst = arg;
	int status;
	pid_t pid;

	(void)fd;
	(void)what;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (pid == inst->xfrpc_pid) {
			inst->xfrpc_pid = -1;
			sm_dispatch(inst, EV_XFRPC_EXITED,
				    (void *)(intptr_t)status);
		}
	}
}

/* ---- PID 文件锁 ---- */

static int lock_and_write_pidfile(inst_t *inst)
{
	char dir[64];
	char *p;
	pid_t old_pid;

	/* 确保父目录存在 */
	snprintf(dir, sizeof(dir), "%s", PID_FILE);
	p = strrchr(dir, '/');
	if (p) {
		*p = 0;
		mkdir(dir, 0755);
	}

	inst->pid_fd = open(PID_FILE, O_RDWR | O_CREAT, 0644);
	if (inst->pid_fd < 0) {
		log_err("cannot open %s: %s", PID_FILE, strerror(errno));
		return -1;
	}

	/* 非阻塞加排他锁，拿到锁说明无其他实例 */
	if (flock(inst->pid_fd, LOCK_EX | LOCK_NB) < 0) {
		char buf[32] = {0};
		old_pid = 0;
		if (pread(inst->pid_fd, buf, sizeof(buf) - 1, 0) > 0)
			old_pid = (pid_t)atoi(buf);
		log_err("another xfrpc_loader is already running (pid=%d), aborting",
			old_pid > 0 ? old_pid : -1);
		close(inst->pid_fd);
		inst->pid_fd = -1;
		return -1;
	}

	/* 锁成功后写入当前 PID */
	char pidbuf[32];
	int n = snprintf(pidbuf, sizeof(pidbuf), "%d\n", getpid());
	ftruncate(inst->pid_fd, 0);
	pwrite(inst->pid_fd, pidbuf, n, 0);
	fsync(inst->pid_fd);
	return 0;
}

/* ---- 命令行帮助 ---- */

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [-f]\n", prog);
	fprintf(stderr, "  -f  run in foreground (log to stderr)\n");
}

/* ---- 公开接口 ---- */

int inst_init(inst_t *inst, int argc, char **argv)
{
	int opt;

	memset(inst, 0, sizeof(*inst));
	inst->pid_fd = -1;
	inst->xfrpc_pid = -1;
	inst->progname = argv[0];

	/* 随机种子：用于 join 重试退避的抖动 */
	srand((unsigned)time(NULL) ^ (unsigned)getpid());

	/* 1. 解析命令行 */
	while ((opt = getopt(argc, argv, "f")) != -1) {
		switch (opt) {
		case 'f':
			inst->foreground = 1;
			break;
		default:
			usage(inst->progname);
			return -1;
		}
	}

	/* 2. 初始化日志 */
	log_init(inst->foreground);
	inst->pid = getpid();
	log_info("xfrpc_loader starting (pid=%d)", inst->pid);

	/* 3. PID 文件锁，确保只一个实例 */
	if (lock_and_write_pidfile(inst) < 0) {
		closelog();
		return -1;
	}

	/* 4. 初始化 libcurl */
	curl_global_init(CURL_GLOBAL_DEFAULT);

	/* 5. 初始化 libevent2 */
	inst->base = event_base_new();
	if (!inst->base) {
		log_err("event_base_new failed");
		inst_cleanup(inst);
		return -1;
	}

	/* 6. 初始化状态机（注册回调表，创建定时器，初始化 auth 上下文） */
	sm_init(inst);

	/* 7. 注册信号事件 */
	inst->ev_term = evsignal_new(inst->base, SIGTERM, on_sigterm_cb, inst);
	inst->ev_int  = evsignal_new(inst->base, SIGINT,  on_sigterm_cb, inst);
	inst->ev_chld = evsignal_new(inst->base, SIGCHLD, on_sigchld_cb, inst);

	if (!inst->ev_term || !inst->ev_int || !inst->ev_chld) {
		log_err("failed to create signal events");
		inst_cleanup(inst);
		return -1;
	}

	event_add(inst->ev_term, NULL);
	event_add(inst->ev_int, NULL);
	event_add(inst->ev_chld, NULL);

	return 0;
}

void inst_cleanup(inst_t *inst)
{
	/* 释放定时器 */
	if (inst->status_timer) {
		event_del(inst->status_timer);
		event_free(inst->status_timer);
		inst->status_timer = NULL;
	}
	if (inst->retry_timer) {
		event_del(inst->retry_timer);
		event_free(inst->retry_timer);
		inst->retry_timer = NULL;
	}
	if (inst->xfrpc_restart_timer) {
		event_del(inst->xfrpc_restart_timer);
		event_free(inst->xfrpc_restart_timer);
		inst->xfrpc_restart_timer = NULL;
	}

	/* 释放信号事件 */
	if (inst->ev_term) {
		event_free(inst->ev_term);
		inst->ev_term = NULL;
	}
	if (inst->ev_int) {
		event_free(inst->ev_int);
		inst->ev_int = NULL;
	}
	if (inst->ev_chld) {
		event_free(inst->ev_chld);
		inst->ev_chld = NULL;
	}

	/* 释放 event_base */
	if (inst->base) {
		event_base_free(inst->base);
		inst->base = NULL;
	}

	/* 解除 PID 文件锁 */
	if (inst->pid_fd >= 0) {
		flock(inst->pid_fd, LOCK_UN);
		close(inst->pid_fd);
		inst->pid_fd = -1;
		unlink(PID_FILE);
	}

	/* libcurl 清理 */
	curl_global_cleanup();

	/* 日志清理 */
	log_info("exited");
	closelog();
}
