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
#ifndef XFRPC_LOADER_AUTH_REMOTE_H
#define XFRPC_LOADER_AUTH_REMOTE_H

#include "config.h"
#include "device_info.h"
#include "session.h"

/*
 * 远程认证结果
 */
typedef struct {
	int		approved;		/* 1=通过，0=拒绝 */
	char		reason[128];		/* 拒绝原因 */
	char		token[256];		/* 认证服务器下发的 token（通过时） */
	char		username[64];		/* 认证通过的用户名（返回给 nginx） */
	char		email[128];		/* 用户邮箱（可选，返回给 nginx） */
} auth_remote_result_t;

/*
 * 向远程服务器发起认证请求。
 *   将解码后的用户名/密码发送到远程 HTTPS 接口进行验证。
 *
 *   cfg        配置（auth_remote_* 字段）
 *   dev        设备信息（device_id, mac 等）
 *   sess       当前会话（session_id）
 *   username   用户名（Basic auth 解码，可为空）
 *   password   密码（Basic auth 解码，可为空）
 *   user_creds 原始 Authorization 头（透传，兼容其他认证方式）
 *   result     输出认证结果
 *
 *   返回 0 成功（不论通过/拒绝），-1 通信失败。
 */
int auth_remote_authenticate(const xfrpc_config_t *cfg,
			     const device_info_t *dev,
			     const session_info_t *sess,
			     const char *username,
			     const char *password,
			     const char *user_creds,
			     auth_remote_result_t *result);

#endif /* XFRPC_LOADER_AUTH_REMOTE_H */
