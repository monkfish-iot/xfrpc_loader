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
 * 发送加入请求（方案 D 公钥钉扎双向认证：请求带 nonce/ts/签名，
 * 响应校验 nonce 回显、时间戳窗口、证书链锚定根 CA 与签名）。
 *
 * 返回值：
 *   0          — 成功（code == 0）且服务器身份验签通过，resp 填充会话信息
 *   -ETIMEDOUT — 超时
 *   -EINTR     — 收到终止信号，curl 被进度回调中止
 *   -EACCES    — 致命：服务端拒绝加入（code == -1001/-1002）或
 *                TLS/证书链/nonce/签名验证失败
 *   -EAGAIN    — 可重试：其他业务负 code 或服务器时间戳越窗
 *   其他负值   — 网络/解析错误
 */
int http_join(const xfrpc_config_t *cfg, const device_info_t *dev,
	      join_response_t *resp, int timeout_sec);

/*
 * 发送状态请求（请求加签绑定 session_id+ts；响应校验时间戳窗口、
 * 单调递增、以 join 时缓存的服务器证书链验签，任一失败按 -EIO
 * 触发重新 join）。
 *
 * 返回值：
 *   0          — 成功（code == 0）且响应验签通过
 *   -ETIMEDOUT — 超时
 *   -EINTR     — 收到终止信号
 *   -EACCES    — TLS 对端校验失败
 *   -EIO       — 业务失败（code != 0）或响应验签失败，调用方重新 join
 *   其他负值   — 网络/解析错误
 */
int http_status(const xfrpc_config_t *cfg, const session_info_t *sess,
		const system_status_t *st, int timeout_sec);

/*
 * 将云端下发的 RADIUS 参数推送到 webauthd 本地配置接口
 * （POST http://127.0.0.1:60000/v1/config/radius/update，部分更新，
 * 幂等）。仅推送 sess 中存在且通过本地逐字段校验的字段，未下发
 * 字段由 webauthd 保持原值。
 *
 * 返回值：
 *   0       — 成功
 *   -EAGAIN — 临时失败（网络/超时/-1004/-1006），应稍后重试
 *   -EACCES — 永久业务拒绝或本地无可推送字段，不重试
 *   -EINTR  — 收到终止信号
 *   -ENOMEM — 内存不足
 */
int http_local_radius_update(const session_info_t *sess, int timeout_sec);

#endif /* XFRPC_LOADER_HTTP_CLIENT_H */
