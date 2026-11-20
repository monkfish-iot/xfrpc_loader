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
#include "system_status.h"
#include "device_info.h"	/* get_if_ip */
#include "log.h"

#include <stdio.h>
#include <string.h>
#include <sys/statvfs.h>

/* 读取文件中的无符号整数 */
static unsigned long read_ulong(const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f)
		return 0;
	unsigned long val = 0;
	fscanf(f, "%lu", &val);
	fclose(f);
	return val;
}

/* 解析 /proc/meminfo */
static void read_meminfo(unsigned long *total, unsigned long *free_val)
{
	FILE *f;
	char line[256];

	*total = *free_val = 0;
	f = fopen("/proc/meminfo", "r");
	if (!f)
		return;

	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "MemTotal:", 9) == 0)
			sscanf(line + 9, "%lu", total);
		else if (strncmp(line, "MemFree:", 8) == 0)
			sscanf(line + 8, "%lu", free_val);
	}
	fclose(f);
}

int system_status_collect(system_status_t *st, const char *local_if)
{
	char path[128];
	struct statvfs vfs;

	memset(st, 0, sizeof(*st));

	/* 设备运行时长：/proc/uptime 第一个字段（秒，浮点） */
	{
		FILE *uf = fopen("/proc/uptime", "r");
		if (uf) {
			double up = 0.0;
			if (fscanf(uf, "%lf", &up) == 1)
				st->uptime = (unsigned long)up;
			fclose(uf);
		}
	}

	/* CPU 温度：/sys/class/thermal/thermal_zone0/temp (毫摄氏度) */
	st->cpu_temp = read_ulong("/sys/class/thermal/thermal_zone0/temp")
		       / 1000.0f;

	/* 内存 */
	read_meminfo(&st->mem_total, &st->mem_free);

	/* 磁盘：根分区 */
	if (statvfs("/", &vfs) == 0) {
		st->disk_total = (unsigned long long)vfs.f_blocks *
				 vfs.f_frsize / 1024;
		st->disk_free = (unsigned long long)vfs.f_bfree *
				vfs.f_frsize / 1024;
	}

	/* 网络流量 + local_if 的 IPv4 */
	if (local_if && local_if[0]) {
		snprintf(path, sizeof(path),
			 "/sys/class/net/%s/statistics/rx_bytes", local_if);
		st->net_rx_bytes = read_ulong(path);

		snprintf(path, sizeof(path),
			 "/sys/class/net/%s/statistics/tx_bytes", local_if);
		st->net_tx_bytes = read_ulong(path);

		get_if_ip(local_if, st->ip, sizeof(st->ip));
	}

	log_debug("status: up=%lus cpu=%.1f℃ mem=%lu/%luKB disk=%lu/%luKB rx=%lu tx=%lu ip=%s",
		  st->uptime, st->cpu_temp, st->mem_free, st->mem_total,
		  st->disk_free, st->disk_total,
		  st->net_rx_bytes, st->net_tx_bytes, st->ip);

	return 0;
}
