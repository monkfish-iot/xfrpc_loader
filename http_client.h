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
#ifndef XFRPC_LOADER_HTTP_CLIENT_H
#define XFRPC_LOADER_HTTP_CLIENT_H

#include "config.h"
#include "device_info.h"
#include "session.h"
#include "system_status.h"
#include "protocol.h"

/*
 * 发送加入请求。
 *
 * 返回值：
 *   0          — 成功（code == 0），resp 填充会话信息
 *   -ETIMEDOUT — 超时
 *   -EACCES    — 服务端拒绝加入（code == -1001/-1002）
 *   其他负值   — 网络/解析错误
 */
int http_join(const xfrpc_config_t *cfg, const device_info_t *dev,
	      join_response_t *resp, int timeout_sec);

/*
 * 发送状态请求。
 *
 * 返回值：
 *   0          — 成功（code == 0）
 *   -ETIMEDOUT — 超时
 *   -EIO       — 业务失败（code != 0），调用方重新 join
 *   其他负值   — 网络/解析错误
 */
int http_status(const xfrpc_config_t *cfg, const session_info_t *sess,
		const system_status_t *st, int timeout_sec);

#endif /* XFRPC_LOADER_HTTP_CLIENT_H */
