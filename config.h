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
#ifndef XFRPC_LOADER_CONFIG_H
#define XFRPC_LOADER_CONFIG_H

#define CONFIG_PATH "/tmp/xfrpc_loader.json"

typedef enum {
	PROTO_HTTP = 0,
	PROTO_HTTPS,
	PROTO_COAP,		/* 预留 */
	PROTO_COAP_TLS,		/* 预留 */
	PROTO_COAP_DTLS,	/* 预留 */
} protocol_t;

typedef struct {
	char		server_name[64];	/* 域名，优先级高于 server_ip；可为空 */
	char		server_ip[64];		/* IP 地址；可为空 */
	int		server_port;		/* 默认 6999 */
	protocol_t	protocol;		/* 默认 HTTPS */
	char		local_if[32];		/* 默认 br-lan */

	int		join_timeout;		/* 加入请求超时(秒)，默认 10 */
	int		status_interval;	/* 状态上报间隔(秒)，默认 60 */
	int		retry_interval;		/* 加入失败初始重试间隔(秒)，默认 5 */
	int		max_retry_interval;	/* 指数退避上限(秒)，默认 300 */
	int		max_join_retries;	/* 0 表示无限重试，默认 0 */

	/* nginx 认证扩展 */
	int		auth_enabled;		/* 是否启用 auth server，默认 0 */
	int		auth_listen_port;	/* 监听端口，默认 8888 */
	protocol_t	auth_remote_proto;	/* 远程认证协议，默认 HTTPS */
	char		auth_remote_host[64];	/* 远程认证地址，空时用 server_name */
	int		auth_remote_port;	/* 远程认证端口，0 时用 server_port */
	char		auth_remote_path[128];	/* 默认 /api/v1/auth */
	int		auth_remote_timeout;	/* 远程认证超时(秒)，默认 10 */
	int		auth_token_cache_ttl;	/* token 缓存时间(秒)，默认 240 */
	int		auth_token_retry_interval; /* token 重试间隔(秒)，默认 5 */

	/* 修改本机密码功能开关（默认关闭）：
	 *   0/关闭：不用随机轮换，改用 default_username/default_password
	 *           写 /etc/config/localpasswd并passwd，测试期彻底锁用户
	 *   1/开启：保留随机轮换逻辑 */
	int		auth_modify_local_password; /* 修改本机密码开关，默认 0(关) */
	char		auth_default_username[64]; /* 默认用户名，默认 root */
	char		auth_default_password[128]; /* 默认密码，默认空 */
} xfrpc_config_t;

/*
 * 从 JSON 文件加载配置。
 * 成功返回 0，失败返回 -1。
 */
int config_load_json(xfrpc_config_t *cfg, const char *path);

/* 协议枚举与字符串互转 */
const char *protocol_str(protocol_t p);
int protocol_parse(const char *s, protocol_t *out);

#endif /* XFRPC_LOADER_CONFIG_H */
