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
#ifndef XFRPC_LOADER_DEVICE_INFO_H
#define XFRPC_LOADER_DEVICE_INFO_H

#include "skey.h"	/* SKEY_DEV_ID_LEN */

/* device_id 的完整缓冲区大小：BASE62 device_id(22) + 本机 MAC 后 4 位 + '\0' */
#define SKEY_DEV_ID_FULL_LEN	(SKEY_DEVICE_ID_BUF + 4)

typedef struct {
	char	board[64];		/* /tmp/sysinfo/board_name */
	char	model[64];		/* /tmp/sysinfo/model */
	char	hostname[64];		/* /proc/sys/kernel/hostname */
	char	ip[64];			/* local_if 的 IPv4 */
	char	mac[32];		/* local_if 接口 MAC，去冒号小写（用于上报/section/subdomain） */
	char	factory_mac[32];	/* skey Factory 分区 MAC，去冒号小写（用于 privilege_key） */
	char	local_if[32];		/* 冗余，便于日志 */
	char	device_id[SKEY_DEV_ID_FULL_LEN];	/* 初始化时已拼上本机 MAC 后 4 位 */
	char	pubkey[SKEY_PUBKEY_LEN];	/* from skey, RSA-2048 PEM */
} device_info_t;

/*
 * 采集本机信息。
 * board/model/hostname/ip 采集失败时填空串，不影响整体。
 * device_id 和 MAC 通过 skey 从 Factory 分区获取，失败时返回 -1。
 * local_if 参数为空时使用 "br-lan"。
 */
int device_info_collect(device_info_t *dev, const char *local_if);

#endif /* XFRPC_LOADER_DEVICE_INFO_H */
