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
#include "device_info.h"
#include "skey.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* 读取文件第一行，去除尾部换行 */
static int read_file_line(const char *path, char *buf, size_t sz)
{
	FILE *f = fopen(path, "r");
	if (!f)
		return -1;
	if (!fgets(buf, sz, f)) {
		fclose(f);
		return -1;
	}
	fclose(f);
	buf[strcspn(buf, "\r\n")] = 0;
	return 0;
}

/* MAC 地址去冒号、转小写：AA:BB:CC:DD:EE:FF -> aabbccddeeff */
static void normalize_mac(const char *in, char *out, size_t sz)
{
	size_t i, j = 0;
	for (i = 0; in[i] && j < sz - 1; i++) {
		if (in[i] != ':' && in[i] != '-')
			out[j++] = tolower((unsigned char)in[i]);
	}
	out[j] = 0;
}

/* 获取指定接口的 IPv4 地址 */
static void get_if_ip(const char *ifname, char *out, size_t sz)
{
	struct ifaddrs *ifap, *ifa;

	out[0] = 0;
	if (getifaddrs(&ifap) < 0)
		return;

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
			continue;
		if (strcmp(ifa->ifa_name, ifname) != 0)
			continue;
		inet_ntop(AF_INET,
			  &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr,
			  out, sz);
		break;
	}
	freeifaddrs(ifap);
}

/* 获取指定接口的 MAC 地址（去冒号小写） */
static void get_if_mac(const char *ifname, char *out, size_t sz)
{
	char path[128];
	char mac_raw[64];

	out[0] = 0;
	snprintf(path, sizeof(path), "/sys/class/net/%s/address", ifname);
	if (read_file_line(path, mac_raw, sizeof(mac_raw)) < 0)
		return;
	normalize_mac(mac_raw, out, sz);
}

/* MAC 是否可用：12 位十六进制、非全零（全零多见于 sit0/tun 等虚拟接口） */
static int mac_is_valid(const char *mac)
{
	size_t i;

	if (strlen(mac) != 12)
		return 0;
	if (strcmp(mac, "000000000000") == 0)
		return 0;
	for (i = 0; i < 12; i++) {
		if (!isxdigit((unsigned char)mac[i]))
			return 0;
	}
	return 1;
}

/*
 * 配置接口取不到 MAC 时，遍历 /sys/class/net 找一个可用接口兜底。
 * 优先选有 IPv4 地址的接口（通常是 br-lan），否则选第一个 MAC 有效的接口。
 * 成功时返回接口名到 out。
 */
static int find_fallback_iface(const char *configured, char *out, size_t sz)
{
	DIR *d;
	struct dirent *e;
	char cand[32] = "";
	char first[32] = "";
	char mac[32];
	char ip[64];

	d = opendir("/sys/class/net");
	if (!d)
		return -1;

	while ((e = readdir(d))) {
		if (e->d_name[0] == '.')
			continue;
		if (strcmp(e->d_name, "lo") == 0)
			continue;
		if (configured && configured[0] &&
		    strcmp(e->d_name, configured) == 0)
			continue;	/* 配置接口已尝试过 */
		get_if_mac(e->d_name, mac, sizeof(mac));
		if (!mac_is_valid(mac))
			continue;
		if (!first[0])
			snprintf(first, sizeof(first), "%s", e->d_name);
		if (!cand[0]) {
			get_if_ip(e->d_name, ip, sizeof(ip));
			if (ip[0])
				snprintf(cand, sizeof(cand), "%s",
					 e->d_name);
		}
	}
	closedir(d);

	if (!cand[0])
		snprintf(cand, sizeof(cand), "%s", first);
	if (!cand[0])
		return -1;

	snprintf(out, sz, "%s", cand);
	return 0;
}

int device_info_collect(device_info_t *dev, const char *local_if)
{
	skey_info_t skey;

	memset(dev, 0, sizeof(*dev));

	if (!local_if || !local_if[0])
		local_if = "br-lan";
	snprintf(dev->local_if, sizeof(dev->local_if), "%s", local_if);

	/* board */
	if (read_file_line("/tmp/sysinfo/board_name", dev->board,
			   sizeof(dev->board)) < 0)
		dev->board[0] = 0;

	/* model */
	if (read_file_line("/tmp/sysinfo/model", dev->model,
			   sizeof(dev->model)) < 0)
		dev->model[0] = 0;

	/* hostname */
	if (read_file_line("/proc/sys/kernel/hostname", dev->hostname,
			   sizeof(dev->hostname)) < 0)
		dev->hostname[0] = 0;

	/* MAC from local_if 接口（用于上报 / xfrpc.ini section/subdomain）。
	 * 配置接口取不到 MAC 时（接口名写错/不存在）自动兜底到其它可用接口，
	 * 否则 join 会因 mac 为空被服务端拒绝。 */
	get_if_mac(local_if, dev->mac, sizeof(dev->mac));
	if (!mac_is_valid(dev->mac)) {
		char fb[32];
		log_warn("local_if %s: MAC unavailable, trying fallback interface",
			 local_if);
		if (find_fallback_iface(local_if, fb, sizeof(fb)) == 0) {
			snprintf(dev->local_if, sizeof(dev->local_if), "%s", fb);
			local_if = dev->local_if;
			get_if_mac(local_if, dev->mac, sizeof(dev->mac));
			log_warn("local_if fallback: using %s (mac=%s)",
				 local_if, dev->mac);
		} else {
			log_err("local_if %s: no usable interface with MAC found",
				local_if);
		}
	}

	/* IP 取最终生效的接口 */
	get_if_ip(local_if, dev->ip, sizeof(dev->ip));

	/* device_id / factory_mac / pubkey from skey（用于身份鉴权） */
	if (skey_get_info(&skey) < 0) {
		log_err("skey_get_info failed, cannot get device identity");
		return -1;
	}
	snprintf(dev->device_id, sizeof(dev->device_id), "%.*s",
		 (int)(SKEY_DEV_ID_LEN - 1), skey.device_id);

#ifdef LOCAL_SKEY
	/* LOCAL_SKEY：factory_mac 直接用 local_if 的 MAC（同一来源） */
	snprintf(dev->factory_mac, sizeof(dev->factory_mac), "%s",
		 dev->mac);
#else
	/* 静态库模式：factory_mac 来自 Factory 分区 */
	snprintf(dev->factory_mac, sizeof(dev->factory_mac), "%s",
		 skey.mac);
#endif
	snprintf(dev->pubkey, sizeof(dev->pubkey), "%s", skey.pubkey);

	log_info("device: board=%s model=%s hostname=%s ip=%s mac=%s(%s) factory_mac=%s device_id=%s if=%s",
		 dev->board, dev->model, dev->hostname,
		 dev->ip, dev->mac, dev->local_if, dev->factory_mac,
		 dev->device_id, dev->local_if);

	return 0;
}
