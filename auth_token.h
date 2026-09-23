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
#ifndef XFRPC_LOADER_AUTH_TOKEN_H
#define XFRPC_LOADER_AUTH_TOKEN_H

#include <time.h>
#include "auth_local.h"

/*
 * LuCI token 缓存
 *   缓存有效的 luci_token_t，避免每次 auth_request 都登录 LuCI。
 *   token 过期后自动失效，需要重新登录。
 */
typedef struct {
	luci_token_t	token;
	time_t		last_fail;	/* 上次登录失败时间 */
	int		cache_ttl;	/* 缓存有效期(秒)，默认 240 */
	int		retry_interval;	/* 登录失败后重试间隔(秒)，默认 5 */
} auth_token_cache_t;

/*
 * 初始化 token 缓存。
 */
void auth_token_cache_init(auth_token_cache_t *cache, int ttl, int retry_int);

/*
 * 获取有效的 LuCI token。
 *   如果缓存有效且未过期，直接返回缓存。
 *   如果缓存过期或无效，用密码登录 LuCI 获取新 token。
 *   如果距离上次登录失败不足 retry_interval 秒，返回 -1 避免频繁重试。
 *   返回 0 成功，-1 失败。
 */
int auth_token_get(auth_token_cache_t *cache, const char *password,
		   luci_token_t *out);

/*
 * 使缓存的 token 失效（登录失败时调用）。
 */
void auth_token_invalidate(auth_token_cache_t *cache);

#endif /* XFRPC_LOADER_AUTH_TOKEN_H */
