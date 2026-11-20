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
#ifndef XFRPC_LOADER_XFRPC_MANAGER_H
#define XFRPC_LOADER_XFRPC_MANAGER_H

#include <sys/types.h>
#include "session.h"
#include "device_info.h"

#define XFRPC_INI_PATH	"/var/etc/xfrpc.ini"
#define XFRPC_BIN_PATH	"/usr/bin/xfrpc"

/*
 * 生成 /var/etc/xfrpc.ini。
 * 成功返回 0，失败返回 -1。
 */
int xfrpc_generate_ini(const session_info_t *sess, const device_info_t *dev);

/*
 * fork + exec xfrpc 子进程。
 * 返回子进程 pid，失败返回 -1。
 */
pid_t xfrpc_spawn(void);

/*
 * 停止 xfrpc 进程：SIGTERM → 等 3 秒 → SIGKILL。
 */
int xfrpc_stop(pid_t pid);

/* 删除 ini 文件 */
void xfrpc_delete_ini(void);

#endif /* XFRPC_LOADER_XFRPC_MANAGER_H */
