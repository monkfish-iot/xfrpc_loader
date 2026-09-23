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
#include "auth_token.h"
#include "log.h"

#include <string.h>

void auth_token_cache_init(auth_token_cache_t *cache, int ttl, int retry_int)
{
	memset(cache, 0, sizeof(*cache));
	cache->cache_ttl = (ttl > 0) ? ttl : 240;
	cache->retry_interval = (retry_int > 0) ? retry_int : 5;
}

int auth_token_get(auth_token_cache_t *cache, const char *password,
		   luci_token_t *out)
{
	time_t now = time(NULL);

	log_info("token cache: checking (valid=%d, ttl=%ds, retry_int=%ds)",
		 cache->token.valid, cache->cache_ttl, cache->retry_interval);

	/* 检查缓存是否有效 */
	if (cache->token.valid) {
		time_t age = now - cache->token.obtained_at;
		time_t expires_at = cache->token.obtained_at + cache->cache_ttl;
		if (now < expires_at) {
			/* 缓存有效 */
			*out = cache->token;
			log_info("token cache: HIT age=%lds (ttl=%ds), "
				 "token=%.16s...",
				 age, cache->cache_ttl, out->token);
			return 0;
		}
		/* 缓存过期 */
		log_info("token cache: EXPIRED age=%lds (ttl=%ds), "
			 "need re-login",
			 age, cache->cache_ttl);
		cache->token.valid = 0;
	} else {
		log_info("token cache: MISS (no valid token), need login");
	}

	/* 检查距离上次失败是否足够 */
	if (cache->last_fail > 0) {
		time_t since_fail = now - cache->last_fail;
		if (since_fail < cache->retry_interval) {
			log_warn("token cache: retry too soon since_fail=%lds "
				 "retry_int=%ds, skip login",
				 since_fail, cache->retry_interval);
			return -1;
		}
		log_info("token cache: retry interval passed since_fail=%lds",
			 since_fail);
	}

	/* 登录 LuCI */
	log_info("token cache: calling luci login (password len=%zu)",
		 password ? strlen(password) : 0);
	if (auth_local_luci_login(password, &cache->token) < 0) {
		cache->last_fail = now;
		log_err("token cache: luci login FAILED, last_fail updated");
		return -1;
	}
	log_info("token cache: luci login OK token=%.16s..., "
		 "stored to cache",
		 cache->token.token);

	cache->last_fail = 0;
	*out = cache->token;
	return 0;
}

void auth_token_invalidate(auth_token_cache_t *cache)
{
	cache->token.valid = 0;
}
