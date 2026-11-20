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
#ifndef XFRPC_LOADER_TIME_SYNC_H
#define XFRPC_LOADER_TIME_SYNC_H

#include "config.h"
#include "protocol.h"

/*
 * 应用服务器下发的时钟/时区信息：
 *   1. |本地时间 - server_time| >= time_sync_threshold 秒时 settimeofday；
 *   2. /etc/config/system 的 timezone/zonename 与下发不一致时改写并 commit；
 *   3. 开启 NTP（system.ntp.enabled=1），下发列表与本地不一致时替换。
 * 未下发、关闭 time_sync_enabled 或无变化时直接返回。
 * 返回 0 成功（含无需变更），-1 参数无效。
 */
int time_sync_apply(const xfrpc_config_t *cfg, const time_info_t *ti);

#endif /* XFRPC_LOADER_TIME_SYNC_H */
