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
#include "config.h"
#include "log.h"

#include <json-c/json.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void set_default(xfrpc_config_t *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->server_port = 6999;
	cfg->protocol = PROTO_HTTPS;
	snprintf(cfg->local_if, sizeof(cfg->local_if), "%s", "br-lan");
	cfg->join_timeout = 10;
	cfg->status_interval = 60;
	cfg->retry_interval = 5;
	cfg->max_retry_interval = 300;	/* 退避上限：默认 5 分钟 */
	cfg->max_join_retries = 0;

	/* auth 默认值 */
	cfg->auth_enabled = 0;
	cfg->auth_listen_port = 8888;
	cfg->auth_remote_proto = PROTO_HTTPS;
	cfg->auth_remote_port = 0;	/* 0 = 用 server_port */
	cfg->auth_remote_timeout = 10;
	cfg->auth_token_cache_ttl = 240;
	cfg->auth_token_retry_interval = 5;
	snprintf(cfg->auth_remote_path, sizeof(cfg->auth_remote_path),
		 "%s", "/api/v1/auth");
	cfg->auth_modify_local_password = 0;	/* 默认关闭 */
	snprintf(cfg->auth_default_username, sizeof(cfg->auth_default_username),
		 "%s", "root");
	cfg->auth_default_password[0] = 0;	/* 默认空 */
}

static void copy_str(char *dst, size_t sz, struct json_object *jv)
{
	if (!jv)
		return;
	const char *s = json_object_get_string(jv);
	if (s)
		snprintf(dst, sz, "%s", s);
}

int config_load_json(xfrpc_config_t *cfg, const char *path)
{
	struct json_object *root, *jserver, *jruntime, *jv;

	set_default(cfg);

	root = json_object_from_file(path);
	if (!root) {
		log_err("cannot load config: %s", path);
		return -1;
	}

	/* server 段 */
	if (json_object_object_get_ex(root, "server", &jserver)) {
		copy_str(cfg->server_name, sizeof(cfg->server_name),
			 json_object_object_get_ex(jserver, "name", &jv) ? jv : NULL);
		copy_str(cfg->server_ip, sizeof(cfg->server_ip),
			 json_object_object_get_ex(jserver, "ip", &jv) ? jv : NULL);
		if (json_object_object_get_ex(jserver, "port", &jv))
			cfg->server_port = json_object_get_int(jv);
		if (json_object_object_get_ex(jserver, "protocol", &jv)) {
			protocol_t p;
			if (protocol_parse(json_object_get_string(jv), &p) < 0) {
				log_err("unsupported protocol: %s",
					json_object_get_string(jv));
				json_object_put(root);
				return -1;
			}
			cfg->protocol = p;
		}
	}

	/* local_if */
	if (json_object_object_get_ex(root, "local_if", &jv))
		copy_str(cfg->local_if, sizeof(cfg->local_if), jv);

	/* runtime 段 */
	if (json_object_object_get_ex(root, "runtime", &jruntime)) {
		if (json_object_object_get_ex(jruntime, "join_timeout", &jv))
			cfg->join_timeout = json_object_get_int(jv);
		if (json_object_object_get_ex(jruntime, "status_interval", &jv))
			cfg->status_interval = json_object_get_int(jv);
		if (json_object_object_get_ex(jruntime, "retry_interval", &jv))
			cfg->retry_interval = json_object_get_int(jv);
		if (json_object_object_get_ex(jruntime, "max_retry_interval", &jv))
			cfg->max_retry_interval = json_object_get_int(jv);
		if (json_object_object_get_ex(jruntime, "max_join_retries", &jv))
			cfg->max_join_retries = json_object_get_int(jv);
	}

	/* auth 段（nginx 认证扩展） */
	{
		struct json_object *jauth;
		if (json_object_object_get_ex(root, "auth", &jauth)) {
			if (json_object_object_get_ex(jauth, "enabled", &jv))
				cfg->auth_enabled = json_object_get_int(jv);
			if (json_object_object_get_ex(jauth, "listen_port", &jv))
				cfg->auth_listen_port = json_object_get_int(jv);
			if (json_object_object_get_ex(jauth, "remote_proto", &jv)) {
				protocol_t p;
				if (protocol_parse(json_object_get_string(jv), &p) == 0)
					cfg->auth_remote_proto = p;
			}
			copy_str(cfg->auth_remote_host, sizeof(cfg->auth_remote_host),
				 json_object_object_get_ex(jauth, "remote_host", &jv) ? jv : NULL);
			if (json_object_object_get_ex(jauth, "remote_port", &jv))
				cfg->auth_remote_port = json_object_get_int(jv);
			copy_str(cfg->auth_remote_path, sizeof(cfg->auth_remote_path),
				 json_object_object_get_ex(jauth, "remote_path", &jv) ? jv : NULL);
			if (json_object_object_get_ex(jauth, "remote_timeout", &jv))
				cfg->auth_remote_timeout = json_object_get_int(jv);
			if (json_object_object_get_ex(jauth, "token_cache_ttl", &jv))
				cfg->auth_token_cache_ttl = json_object_get_int(jv);
			if (json_object_object_get_ex(jauth, "token_retry_interval", &jv))
				cfg->auth_token_retry_interval = json_object_get_int(jv);
			if (json_object_object_get_ex(jauth, "modify_local_password", &jv))
				cfg->auth_modify_local_password = json_object_get_int(jv);
			copy_str(cfg->auth_default_username,
				 sizeof(cfg->auth_default_username),
				 json_object_object_get_ex(jauth,
							  "default_username", &jv) ? jv : NULL);
			copy_str(cfg->auth_default_password,
				 sizeof(cfg->auth_default_password),
				 json_object_object_get_ex(jauth,
							  "default_password", &jv) ? jv : NULL);
		}
	}

	json_object_put(root);

	/* 校验 */
	if (!cfg->server_name[0] && !cfg->server_ip[0]) {
		log_err("either server_name or server_ip must be configured");
		return -1;
	}
	if (cfg->protocol != PROTO_HTTP && cfg->protocol != PROTO_HTTPS) {
		log_err("only http/https supported currently");
		return -1;
	}
	if (cfg->server_port <= 0 || cfg->server_port > 65535) {
		log_err("invalid server_port: %d", cfg->server_port);
		return -1;
	}
	if (cfg->join_timeout <= 0)
		cfg->join_timeout = 10;
	if (cfg->status_interval <= 0)
		cfg->status_interval = 60;
	if (cfg->retry_interval <= 0)
		cfg->retry_interval = 5;
	if (cfg->max_retry_interval <= 0)
		cfg->max_retry_interval = 300;
	if (cfg->max_retry_interval < cfg->retry_interval)
		cfg->max_retry_interval = cfg->retry_interval;

	/* auth 默认值回退 */
	if (!cfg->auth_remote_host[0]) {
		snprintf(cfg->auth_remote_host,
			 sizeof(cfg->auth_remote_host), "%s",
			 cfg->server_name[0] ? cfg->server_name
					      : cfg->server_ip);
	}
	if (cfg->auth_remote_port == 0)
		cfg->auth_remote_port = cfg->server_port;

	log_info("config loaded: server=%s://%s:%d, local_if=%s",
		 protocol_str(cfg->protocol),
		 cfg->server_name[0] ? cfg->server_name : cfg->server_ip,
		 cfg->server_port, cfg->local_if);
	if (cfg->auth_enabled) {
		log_info("auth: enabled, listen=%d, remote=%s://%s:%d%s",
			 cfg->auth_listen_port,
			 protocol_str(cfg->auth_remote_proto),
			 cfg->auth_remote_host,
			 cfg->auth_remote_port,
			 cfg->auth_remote_path);
	}

	return 0;
}

const char *protocol_str(protocol_t p)
{
	switch (p) {
	case PROTO_HTTP:	return "http";
	case PROTO_HTTPS:	return "https";
	case PROTO_COAP:	return "coap";
	case PROTO_COAP_TLS:	return "coap_tls";
	case PROTO_COAP_DTLS:	return "coap_dtls";
	default:		return "unknown";
	}
}

int protocol_parse(const char *s, protocol_t *out)
{
	if (!s)
		return -1;
	if (strcmp(s, "http") == 0)		{ *out = PROTO_HTTP;	return 0; }
	if (strcmp(s, "https") == 0)		{ *out = PROTO_HTTPS;	return 0; }
	if (strcmp(s, "coap") == 0)		{ *out = PROTO_COAP;	return 0; }
	if (strcmp(s, "coap_tls") == 0)		{ *out = PROTO_COAP_TLS; return 0; }
	if (strcmp(s, "coap_dtls") == 0)	{ *out = PROTO_COAP_DTLS; return 0; }
	return -1;
}
