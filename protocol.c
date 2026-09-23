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
#include "protocol.h"
#include "log.h"

#include <json-c/json.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ---- 请求构造 ---- */

char *protocol_build_join_request(const device_info_t *dev)
{
	struct json_object *root;
	const char *s;
	char *result;

	/* 公钥必须存在，否则拒绝发送加入请求 */
	if (!dev->pubkey[0]) {
		log_err("获取公钥失败，无法发送加入请求");
		return NULL;
	}

	root = json_object_new_object();
	json_object_object_add(root, "device_id",
		json_object_new_string(dev->device_id[0] ? dev->device_id : ""));
	json_object_object_add(root, "board",
		json_object_new_string(dev->board[0] ? dev->board : ""));
	json_object_object_add(root, "model",
		json_object_new_string(dev->model[0] ? dev->model : ""));
	json_object_object_add(root, "hostname",
		json_object_new_string(dev->hostname[0] ? dev->hostname : ""));
	json_object_object_add(root, "ip",
		json_object_new_string(dev->ip[0] ? dev->ip : ""));
	json_object_object_add(root, "mac",
		json_object_new_string(dev->mac[0] ? dev->mac : ""));
	json_object_object_add(root, "local_if",
		json_object_new_string(dev->local_if));
	json_object_object_add(root, "pub_key",
		json_object_new_string(dev->pubkey));

	s = json_object_to_json_string(root);
	result = strdup(s);
	json_object_put(root);

	log_debug("join request: %s", result ? result : "(null)");
	return result;
}

char *protocol_build_status_request(const system_status_t *st)
{
	struct json_object *root;
	const char *s;
	char *result;

	root = json_object_new_object();
	json_object_object_add(root, "cpu_temp",
		json_object_new_double(st->cpu_temp));
	json_object_object_add(root, "mem_total",
		json_object_new_int64(st->mem_total));
	json_object_object_add(root, "mem_free",
		json_object_new_int64(st->mem_free));
	json_object_object_add(root, "disk_total",
		json_object_new_int64(st->disk_total));
	json_object_object_add(root, "disk_free",
		json_object_new_int64(st->disk_free));
	json_object_object_add(root, "net_rx_bytes",
		json_object_new_int64(st->net_rx_bytes));
	json_object_object_add(root, "net_tx_bytes",
		json_object_new_int64(st->net_tx_bytes));

	s = json_object_to_json_string(root);
	result = strdup(s);
	json_object_put(root);

	return result;
}

/* ---- 响应解析 ---- */

int protocol_parse_join_response(const char *body, join_response_t *resp,
				 int *code, char *msg, size_t msg_sz)
{
	struct json_object *root, *jcode, *jmsg, *jdata, *jsid, *jxfrpc;
	struct json_object *jaddr, *jport;

	*code = -1;
	if (msg && msg_sz)
		msg[0] = 0;
	memset(resp, 0, sizeof(*resp));

	root = json_tokener_parse(body);
	if (!root) {
		log_err("join response: JSON parse error");
		return -1;
	}

	if (json_object_object_get_ex(root, "error_code", &jcode))
		*code = json_object_get_int(jcode);
	if (json_object_object_get_ex(root, "msg", &jmsg) && msg) {
		const char *s = json_object_get_string(jmsg);
		snprintf(msg, msg_sz, "%s", s ? s : "");
	}

	if (*code < 0) {
		json_object_put(root);
		return 0;	/* 解析成功，但业务失败 */
	}

	/* error_code == 0，提取 body */
	if (json_object_object_get_ex(root, "body", &jdata)) {
		struct json_object *jcakey;
		if (json_object_object_get_ex(jdata, "session_id", &jsid)) {
			const char *s = json_object_get_string(jsid);
			snprintf(resp->session_id, sizeof(resp->session_id), "%s",
			 s ? s : "");
		}
		if (json_object_object_get_ex(jdata, "ca_pub_key", &jcakey)) {
			const char *s = json_object_get_string(jcakey);
			snprintf(resp->ca_pub_key, sizeof(resp->ca_pub_key), "%s",
			 s ? s : "");
		}
		if (json_object_object_get_ex(jdata, "xfrpc", &jxfrpc)) {
			if (json_object_object_get_ex(jxfrpc, "server_addr",
						     &jaddr)) {
				const char *s = json_object_get_string(jaddr);
				snprintf(resp->xfrpc_server_addr,
			 sizeof(resp->xfrpc_server_addr), "%s",
			 s ? s : "");
			}
			if (json_object_object_get_ex(jxfrpc, "server_port",
						     &jport))
				resp->xfrpc_server_port = json_object_get_int(jport);
		}
	}

	json_object_put(root);

	/* 校验必要字段 */
	if (!resp->session_id[0] || !resp->xfrpc_server_addr[0] ||
	    resp->xfrpc_server_port <= 0) {
		log_err("join response: missing required fields");
		return -1;
	}

	log_debug("join response: session=%s xfrpc=%s:%d",
		  resp->session_id, resp->xfrpc_server_addr,
		  resp->xfrpc_server_port);
	return 0;
}

int protocol_parse_status_response(const char *body, int *code,
				   char *msg, size_t msg_sz)
{
	struct json_object *root, *jcode, *jmsg;

	*code = -1;
	if (msg && msg_sz)
		msg[0] = 0;

	root = json_tokener_parse(body);
	if (!root) {
		log_err("status response: JSON parse error");
		return -1;
	}

	if (json_object_object_get_ex(root, "error_code", &jcode))
		*code = json_object_get_int(jcode);
	if (json_object_object_get_ex(root, "msg", &jmsg) && msg) {
		const char *s = json_object_get_string(jmsg);
		snprintf(msg, msg_sz, "%s", s ? s : "");
	}

	json_object_put(root);
	return 0;
}
