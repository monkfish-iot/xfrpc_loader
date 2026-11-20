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

/* ---- 终止信号（SIGINT/SIGTERM）：sigaction + self-pipe ---- */

volatile sig_atomic_t g_terminate_requested = 0;

/* 信号处理函数的写端（单实例，PID 锁保证唯一，无需经参数传递） */
static int s_sig_pipe_wr = -1;

/* 仅做 async-signal-safe 操作：置标志 + 写一字节唤醒事件循环 */
static void term_signal_handler(int sig)
{
	int saved_errno = errno;
	unsigned char b = 1;

	(void)sig;
	g_terminate_requested = 1;
	if (s_sig_pipe_wr >= 0) {
		ssize_t n = write(s_sig_pipe_wr, &b, 1);
		(void)n;	/* 管道满(EAGAIN)无妨，标志已置位 */
	}
	errno = saved_errno;
}

/* self-pipe 读端就绪：排空管道后向状态机派发终止事件 */
static void on_sig_pipe_cb(evutil_socket_t fd, short what, void *arg)
{
	inst_t *inst = arg;
	char drain[16];

	(void)what;
	while (read(fd, drain, sizeof(drain)) > 0)
		;
	log_info("received termination signal");
	sm_dispatch(inst, EV_SIGTERM, NULL);
}

/* 安装 SIGINT/SIGTERM：sigaction + 非阻塞 self-pipe 接入 libevent。
 * sa_flags 不带 SA_RESTART，被中断的 poll/connect 尽快返回，配合
 * curl 进度回调实现秒级中止。返回 0 成功，-1 失败。 */
static int install_term_signals(inst_t *inst)
{
	struct sigaction sa;

	inst->sig_pipe[0] = inst->sig_pipe[1] = -1;

	/* 纯 POSIX 方式（不依赖 pipe2，musl/uclibc/glibc 均可用） */
	if (pipe(inst->sig_pipe) < 0) {
		log_err("pipe failed: %s", strerror(errno));
		return -1;
	}
	fcntl(inst->sig_pipe[0], F_SETFL, O_NONBLOCK);
	fcntl(inst->sig_pipe[1], F_SETFL, O_NONBLOCK);
	fcntl(inst->sig_pipe[0], F_SETFD, FD_CLOEXEC);
	fcntl(inst->sig_pipe[1], F_SETFD, FD_CLOEXEC);

	inst->ev_sig = event_new(inst->base, inst->sig_pipe[0],
				 EV_READ | EV_PERSIST, on_sig_pipe_cb, inst);
	if (!inst->ev_sig) {
		log_err("event_new(sig_pipe) failed");
		close(inst->sig_pipe[0]);
		close(inst->sig_pipe[1]);
		inst->sig_pipe[0] = inst->sig_pipe[1] = -1;
		return -1;
	}
	event_add(inst->ev_sig, NULL);

	s_sig_pipe_wr = inst->sig_pipe[1];

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = term_signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGINT, &sa, NULL) < 0 ||
	    sigaction(SIGTERM, &sa, NULL) < 0) {
		log_err("sigaction failed: %s", strerror(errno));
		return -1;
	}

	/* curl 已设 CURLOPT_NOSIGNAL，这里显式忽略 SIGPIPE 做双保险 */
	signal(SIGPIPE, SIG_IGN);
	return 0;
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
	inst->sig_pipe[0] = inst->sig_pipe[1] = -1;	/* fd 0 是 stdin，必须显式置 -1 */
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

	/* 6.1 启动 webauthd 控制通道。失败仅告警：
	 *     webauthd 会按本地基线运行，不影响 xfrpc_loader 主流程。 */
	if (control_server_start(&inst->control, inst->base, inst) < 0)
		log_warn("failed to start webauthd control server");

	/* 7. 注册终止信号（sigaction + self-pipe，保证同步 curl 阻塞期间
	 *    Ctrl+C 也能秒级中止）与 SIGCHLD（libevent evsignal） */
	if (install_term_signals(inst) < 0) {
		log_err("failed to install termination signals");
		inst_cleanup(inst);
		return -1;
	}
	inst->ev_chld = evsignal_new(inst->base, SIGCHLD, on_sigchld_cb, inst);
	if (!inst->ev_chld) {
		log_err("failed to create SIGCHLD event");
		inst_cleanup(inst);
		return -1;
	}
	event_add(inst->ev_chld, NULL);

	return 0;
}

void inst_cleanup(inst_t *inst)
{
	/* 先停止控制面监听，避免 event_base 释放后仍有回调 */
	control_server_stop(&inst->control);

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

	/* 释放信号相关资源 */
	if (inst->ev_chld) {
		event_free(inst->ev_chld);
		inst->ev_chld = NULL;
	}
	if (inst->ev_sig) {
		event_free(inst->ev_sig);	/* 普通事件不拥有 fd，下面手动关 */
		inst->ev_sig = NULL;
	}
	s_sig_pipe_wr = -1;
	if (inst->sig_pipe[0] >= 0) {
		close(inst->sig_pipe[0]);
		inst->sig_pipe[0] = -1;
	}
	if (inst->sig_pipe[1] >= 0) {
		close(inst->sig_pipe[1]);
		inst->sig_pipe[1] = -1;
	}
	/* 恢复终止信号默认处置（进程退出前清理，避免影响异常路径） */
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);

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
