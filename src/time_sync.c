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
#include "time_sync.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>

/* ---- 本地工具 ---- */

/* 执行 shell 命令，返回 0 成功 */
static int run_cmd(const char *cmd)
{
	int rc = system(cmd);

	return rc == 0 ? 0 : -1;
}

/*
 * 读取 uci 配置项（uci -q get <key>），取首行并去除首尾空白。
 * 失败或不存在时输出空串，返回 -1。
 */
static int uci_get(const char *key, char *out, size_t sz)
{
	char cmd[256];
	FILE *f;
	size_t n;

	if (!out || sz == 0)
		return -1;
	out[0] = 0;

	snprintf(cmd, sizeof(cmd), "uci -q get %s 2>/dev/null", key);
	f = popen(cmd, "r");
	if (!f)
		return -1;
	if (fgets(out, (int)sz, f) == NULL)
		out[0] = 0;
	pclose(f);

	n = strlen(out);
	while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r' ||
			 out[n - 1] == ' ' || out[n - 1] == '\t'))
		out[--n] = 0;
	return out[0] ? 0 : -1;
}

/*
 * 字符集校验：值来自服务器下发，写入 uci/shell 前必须限制字符，
 * 避免单引号等元字符注入命令；非法值直接忽略（不影响主流程）。
 */
static int valid_charset(const char *s, const char *extra)
{
	const char *p;

	if (!s || !s[0])
		return 0;
	for (p = s; *p; p++) {
		if (isalnum((unsigned char)*p))
			continue;
		if (extra && strchr(extra, *p))
			continue;
		return 0;
	}
	return 1;
}

/* POSIX TZ 串：CST-8 / UTC0 / <+08>-8 / EST5EDT,M3.2.0,M11.1.0 */
static int tz_posix_valid(const char *s)
{
	return valid_charset(s, "+-:,.<>");
}

/* IANA 时区名：Asia/Shanghai、Etc/GMT-8 */
static int tz_iana_valid(const char *s)
{
	return valid_charset(s, "/_+-");
}

/* NTP 服务器地址：域名或 IP */
static int ntp_server_valid(const char *s)
{
	if (!valid_charset(s, ".-_:+/"))
		return 0;
	/* 不允许以 '-' 开头（避免被当作命令参数） */
	return s[0] != '-';
}

/* ---- 时间校正 ---- */

static void sync_clock(long server_time, int threshold)
{
	struct timeval tv;
	long delta = server_time - (long)time(NULL);

	if (delta < 0)
		delta = -delta;

	if (delta < threshold) {
		log_debug("clock ok: local=%ld server=%ld diff=%lds < threshold=%ds",
			  (long)time(NULL), server_time, delta, threshold);
		return;
	}

	tv.tv_sec = (time_t)server_time;
	tv.tv_usec = 0;
	if (settimeofday(&tv, NULL) < 0) {
		log_err("settimeofday failed: %s", strerror(errno));
		return;
	}
	log_info("clock adjusted: server_time=%ld, diff=%lds (threshold=%ds)",
		 server_time, delta, threshold);
}

/* ---- 时区 ---- */

static int sync_timezone(const time_info_t *ti)
{
	char cur[TIME_INFO_TZ_LEN];
	char cmd[256];
	int changed = 0;

	if (ti->tz_posix[0] && tz_posix_valid(ti->tz_posix)) {
		if (uci_get("system.@system[0].timezone", cur, sizeof(cur)) < 0 ||
		    strcmp(cur, ti->tz_posix) != 0) {
			snprintf(cmd, sizeof(cmd),
				 "uci set system.@system[0].timezone='%s'",
				 ti->tz_posix);
			if (run_cmd(cmd) == 0) {
				log_info("timezone set to '%s' (was '%s')",
					 ti->tz_posix, cur);
				changed = 1;
			} else {
				log_warn("uci set timezone failed");
			}
		}
	} else if (ti->tz_posix[0]) {
		log_warn("ignore invalid tz_posix '%s'", ti->tz_posix);
	}

	if (ti->tz_iana[0] && tz_iana_valid(ti->tz_iana)) {
		if (uci_get("system.@system[0].zonename", cur, sizeof(cur)) < 0 ||
		    strcmp(cur, ti->tz_iana) != 0) {
			snprintf(cmd, sizeof(cmd),
				 "uci set system.@system[0].zonename='%s'",
				 ti->tz_iana);
			if (run_cmd(cmd) == 0) {
				log_info("zonename set to '%s' (was '%s')",
					 ti->tz_iana, cur);
				changed = 1;
			} else {
				log_warn("uci set zonename failed");
			}
		}
	} else if (ti->tz_iana[0]) {
		log_warn("ignore invalid tz_iana '%s'", ti->tz_iana);
	}

	return changed;
}

/* ---- NTP ---- */

static int sync_ntp(const time_info_t *ti)
{
	char cur[512];
	char cmd[256];
	char list[TIME_INFO_NTP_LEN];
	char *tok, *save = NULL;
	int changed = 0;

	/* 默认开启 NTP 同步 */
	if (uci_get("system.ntp.enabled", cur, sizeof(cur)) < 0 ||
	    strcmp(cur, "1") != 0) {
		if (run_cmd("uci set system.ntp.enabled='1'") == 0) {
			log_info("ntp enabled (was '%s')", cur);
			changed = 1;
		} else {
			log_warn("uci set ntp.enabled failed");
		}
	}

	if (!ti->ntp_servers[0])
		return changed;

	/* uci get 对 list 返回空格分隔的单行；与下发列表逐字比较 */
	cur[0] = 0;
	(void)uci_get("system.ntp.server", cur, sizeof(cur));
	if (strcmp(cur, ti->ntp_servers) == 0)
		return changed;

	snprintf(list, sizeof(list), "%s", ti->ntp_servers);
	if (run_cmd("uci -q delete system.ntp.server") < 0) {
		log_warn("uci delete ntp.server failed");
		return changed;
	}
	for (tok = strtok_r(list, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
		if (!ntp_server_valid(tok)) {
			log_warn("ignore invalid ntp server '%s'", tok);
			continue;
		}
		snprintf(cmd, sizeof(cmd), "uci add_list system.ntp.server='%s'", tok);
		if (run_cmd(cmd) < 0) {
			log_warn("uci add_list ntp.server '%s' failed", tok);
			continue;
		}
		changed = 1;
	}
	if (changed)
		log_info("ntp servers set to '%s' (was '%s')",
			 ti->ntp_servers, cur);
	return changed;
}

/* ---- 对外接口 ---- */

int time_sync_apply(const xfrpc_config_t *cfg, const time_info_t *ti)
{
	int threshold;
	int tz_changed, ntp_changed;

	if (!cfg || !ti || !cfg->time_sync_enabled)
		return 0;
	if (ti->server_time <= 0)
		return 0;

	threshold = cfg->time_sync_threshold > 0 ?
		    cfg->time_sync_threshold : 5;
	sync_clock(ti->server_time, threshold);

	tz_changed = sync_timezone(ti);
	ntp_changed = sync_ntp(ti);

	if (tz_changed || ntp_changed) {
		if (run_cmd("uci commit system") < 0)
			log_err("uci commit system failed");
		else
			log_debug("uci commit system ok");
	}
	if (tz_changed)
		(void)run_cmd("/etc/init.d/system reload 2>/dev/null");
	if (ntp_changed)
		(void)run_cmd("/etc/init.d/sysntpd restart 2>/dev/null");

	return 0;
}
