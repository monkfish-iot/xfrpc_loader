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
#ifndef XFRPC_LOADER_SYSTEM_STATUS_H
#define XFRPC_LOADER_SYSTEM_STATUS_H

typedef struct {
	float		cpu_temp;		/* ℃ */
	unsigned long	mem_total;		/* KB */
	unsigned long	mem_free;		/* KB */
	unsigned long	disk_total;		/* KB */
	unsigned long	disk_free;		/* KB */
	unsigned long	net_rx_bytes;		/* bytes */
	unsigned long	net_tx_bytes;		/* bytes */
} system_status_t;

/*
 * 采集系统状态。
 * 个别字段采集失败时填 0，不影响整体。
 */
int system_status_collect(system_status_t *st, const char *local_if);

#endif /* XFRPC_LOADER_SYSTEM_STATUS_H */
