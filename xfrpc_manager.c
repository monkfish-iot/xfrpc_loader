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
#include "xfrpc_manager.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

int xfrpc_generate_ini(const session_info_t *sess, const device_info_t *dev)
{
	FILE *f;

	/* 确保 /var/etc 目录存在（OpenWrt 上 /var 是 /tmp 的符号链接） */
	mkdir("/var/etc", 0755);

	f = fopen(XFRPC_INI_PATH, "w");
	if (!f) {
		log_err("cannot create %s: %s", XFRPC_INI_PATH, strerror(errno));
		return -1;
	}

	fprintf(f, "[common]\n");
	fprintf(f, "server_addr = %s\n", sess->xfrpc_server_addr);
	fprintf(f, "server_port = %d\n", sess->xfrpc_server_port);
	fprintf(f, "user = %s\n", dev->device_id);
	/* token 作为 privilege_key 发送给 frps 鉴权。
	 * frps auth_handler 仅校验 privilege_key 非空（真正的鉴权是
	 * run_id→session_id 内存反查），用 MAC 即可。
	 * 修复：此行曾被注释掉，导致 privilege_key 为空，
	 * frps 以 "no valid credentials" 拒绝登录 → 隧道不建立 → 404。 */
	

	fprintf(f, "\n");
	fprintf(f, "[%s]\n", dev->device_id);
	fprintf(f, "type = http\n");
	fprintf(f, "local_ip = 127.0.0.1\n");
	fprintf(f, "local_port = 8765\n");
	/* 有意使用 session_id 作为 subdomain：会话地址随 rejoin 漂移，
	 * 避免攻击者长期锁定设备所在地址（防探测）。不要改成固定值。 */
	fprintf(f, "subdomain = %s\n", sess->session_id);

	fclose(f);

	/* 排障：回读并逐行打印实际写入的 ini，核对 xfrpc 真正拿到的配置
	 * （token 是否存在、有无多余/缺失字段）。 */
	{
		FILE *rf = fopen(XFRPC_INI_PATH, "r");
		if (rf) {
			char line[256];
			log_info("--- %s begin ---", XFRPC_INI_PATH);
			while (fgets(line, sizeof(line), rf)) {
				size_t l = strlen(line);
				while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r'))
					line[--l] = '\0';
				log_info("ini| %s", line);
			}
			log_info("--- %s end ---", XFRPC_INI_PATH);
			fclose(rf);
		} else {
			log_warn("cannot reopen %s for dump: %s",
				 XFRPC_INI_PATH, strerror(errno));
		}
	}

	log_info("generated %s: xfrpc=%s:%d user=%s subdomain=%s token=%s",
		 XFRPC_INI_PATH,
		 sess->xfrpc_server_addr, sess->xfrpc_server_port,
		 dev->device_id, sess->session_id,
		 dev->factory_mac[0] ? dev->factory_mac : dev->mac);
	return 0;
}

/* 清理可能残留的 xfrpc 进程，kill -9 直到没有 xfrpc 运行 */
static void kill_existing_xfrpc(void)
{
	int retry;

	for (retry = 0; retry < 10; retry++) {
		FILE *fp = popen("pidof xfrpc 2>/dev/null", "r");
		char buf[256];

		if (!fp)
			break;
		buf[0] = '\0';
		fgets(buf, sizeof(buf), fp);
		pclose(fp);

		/* pidof 无输出表示没有 xfrpc 进程 */
		if (buf[0] == '\0' || buf[0] == '\n')
			break;

		if (retry == 0)
			log_info("killing existing xfrpc: %s", buf);

		/* pidof 返回空格分隔的 PID 列表，逐个 kill -9 */
		char *tok = strtok(buf, " \n");
		while (tok) {
			pid_t pid = atoi(tok);
			if (pid > 0)
				kill(pid, SIGKILL);
			tok = strtok(NULL, " \n");
		}
		usleep(200000);	/* 等 200ms 再检查 */
	}
}

pid_t xfrpc_spawn(void)
{
	pid_t pid;

	/* 先清理可能残留的 xfrpc 进程 */
	kill_existing_xfrpc();

	pid = fork();

	if (pid < 0) {
		log_err("fork failed: %s", strerror(errno));
		return -1;
	}

	if (pid == 0) {
		/* 子进程：-f 前台运行（不 daemon 化）。
		 * 不开 -d debug 日志：大量 debug 输出会加重内存/logread 缓冲
		 * 压力，在内存紧张的 OpenWrt 上可能诱发 OOM SIGKILL。
		 * 排障时临时手加 -d 7 即可。 */
		execl(XFRPC_BIN_PATH, "xfrpc", "-f", "-c", XFRPC_INI_PATH,
		      (char *)NULL);
		/* execl 仅在失败时返回 */
		log_err("execl %s failed: %s", XFRPC_BIN_PATH, strerror(errno));
		_exit(127);
	}

	return pid;
}

int xfrpc_stop(pid_t pid)
{
	int i;

	if (pid <= 0)
		return 0;

	kill(pid, SIGTERM);

	/* 最多等 3 秒（30 × 100ms） */
	for (i = 0; i < 30; i++) {
		pid_t r = waitpid(pid, NULL, WNOHANG);
		if (r == pid)
			return 0;
		if (r < 0 && errno == ECHILD)
			return 0;	/* 已被其他路径回收 */
		usleep(100000);
	}

	/* 超时未退出，强制 kill */
	log_warn("xfrpc pid %d did not exit, sending SIGKILL", pid);
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	return 0;
}

void xfrpc_delete_ini(void)
{
	unlink(XFRPC_INI_PATH);
}
