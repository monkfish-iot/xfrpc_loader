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
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>

/* ---- 通用辅助 ---- */

static void jstr_add(struct json_object *root, const char *key, const char *val)
{
	json_object_object_add(root, key,
		json_object_new_string(val ? val : ""));
}

int protocol_sha256_hex(const char *in, char *out_hex)
{
	EVP_MD_CTX *ctx;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_len = 0;
	static const char hexchars[] = "0123456789abcdef";
	unsigned int i;
	int ok = 0;

	if (!out_hex)
		return -1;

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return -1;

	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(ctx, in ? in : "", in ? strlen(in) : 0) == 1 &&
	    EVP_DigestFinal_ex(ctx, digest, &digest_len) == 1)
		ok = 1;

	EVP_MD_CTX_free(ctx);

	if (!ok || digest_len != 32) {
		log_err("sha256 compute failed");
		return -1;
	}

	for (i = 0; i < digest_len; i++) {
		out_hex[i * 2]     = hexchars[(digest[i] >> 4) & 0xF];
		out_hex[i * 2 + 1] = hexchars[digest[i] & 0xF];
	}
	out_hex[digest_len * 2] = 0;
	return 0;
}

/* ---- 签名原文（canonical text） ---- */

int protocol_canon_join_req(const device_info_t *dev,
			    const char *nonce, long ts,
			    char *out, size_t out_sz)
{
	char hpk[65];
	int n;

	if (!dev || !nonce || !out)
		return -1;

	/* 末行绑定公钥摘要（方案 D：签名验证用请求中的同一公钥，
	 * 证明持有对应私钥，防止公钥抢注） */
	if (protocol_sha256_hex(dev->pubkey[0] ? dev->pubkey : "",
				hpk) < 0)
		return -1;

	n = snprintf(out, out_sz,
		     "xfrpc-auth-v1\njoin\n%s\n%s\n%s\n%ld\n%s",
		     dev->device_id[0] ? dev->device_id : "",
		     dev->mac[0] ? dev->mac : "",
		     nonce, ts, hpk);
	if (n < 0 || (size_t)n >= out_sz)
		return -1;
	return 0;
}

int protocol_canon_join_resp(const char *device_id,
			     const join_response_t *resp,
			     char *out, size_t out_sz)
{
	int n;

	if (!device_id || !resp || !out)
		return -1;

	n = snprintf(out, out_sz,
		     "xfrpc-auth-v1\njoin-resp\n%s\n%s\n%ld\n%s\n%s\n%d",
		     device_id,
		     resp->nonce[0] ? resp->nonce : "",
		     resp->ts,
		     resp->session_id,
		     resp->xfrpc_server_addr,
		     resp->xfrpc_server_port);
	if (n < 0 || (size_t)n >= out_sz)
		return -1;
	return 0;
}

int protocol_canon_status_req(const char *session_id, long ts,
			      char *out, size_t out_sz)
{
	int n;

	if (!session_id || !out)
		return -1;

	n = snprintf(out, out_sz,
		     "xfrpc-auth-v1\nstatus\n%s\n%ld", session_id, ts);
	if (n < 0 || (size_t)n >= out_sz)
		return -1;
	return 0;
}

int protocol_canon_status_resp(const char *session_id, long ts, int code,
			       char *out, size_t out_sz)
{
	int n;

	if (!session_id || !out)
		return -1;

	n = snprintf(out, out_sz,
		     "xfrpc-auth-v1\nstatus-resp\n%s\n%ld\n%d",
		     session_id, ts, code);
	if (n < 0 || (size_t)n >= out_sz)
		return -1;
	return 0;
}

int protocol_canon_auth_req(const char *session_id, long ts,
			    const char *username, const char *password,
			    const char *credentials,
			    char *out, size_t out_sz)
{
	char hu[65], hp[65], hc[65];

	if (!session_id || !out)
		return -1;

	if (protocol_sha256_hex(username, hu) < 0 ||
	    protocol_sha256_hex(password, hp) < 0 ||
	    protocol_sha256_hex(credentials, hc) < 0)
		return -1;

	int n = snprintf(out, out_sz,
			 "xfrpc-auth-v1\nauth\n%s\n%ld\n%s\n%s\n%s",
			 session_id, ts, hu, hp, hc);
	if (n < 0 || (size_t)n >= out_sz)
		return -1;
	return 0;
}

int protocol_canon_auth_resp(const char *session_id, long ts, int code,
			     char *out, size_t out_sz)
{
	int n;

	if (!session_id || !out)
		return -1;

	n = snprintf(out, out_sz,
		     "xfrpc-auth-v1\nauth-resp\n%s\n%ld\n%d",
		     session_id, ts, code);
	if (n < 0 || (size_t)n >= out_sz)
		return -1;
	return 0;
}

/* ---- 请求构造 ---- */

char *protocol_build_join_request(const device_info_t *dev,
				  const join_auth_t *auth)
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
	jstr_add(root, "device_id", dev->device_id[0] ? dev->device_id : "");
	jstr_add(root, "board", dev->board[0] ? dev->board : "");
	jstr_add(root, "model", dev->model[0] ? dev->model : "");
	jstr_add(root, "hostname", dev->hostname[0] ? dev->hostname : "");
	jstr_add(root, "ip", dev->ip[0] ? dev->ip : "");
	jstr_add(root, "mac", dev->mac[0] ? dev->mac : "");
	jstr_add(root, "local_if", dev->local_if);
	jstr_add(root, "pub_key", dev->pubkey);

	/* 双向认证材料（方案 D 公钥钉扎）：
	 * 设备公钥已随 pub_key 字段上报供服务器钉扎/验签，
	 * 此处附加 nonce + 时间戳 + 私钥签名（设备不出示证书链）。 */
	if (auth && auth->signature && auth->signature[0]) {
		jstr_add(root, "nonce", auth->nonce);
		json_object_object_add(root, "ts",
			json_object_new_int64(auth->ts));
		jstr_add(root, "signature", auth->signature);
	}

	s = json_object_to_json_string(root);
	result = strdup(s);
	json_object_put(root);

	log_debug("join request: %s", result ? result : "(null)");
	return result;
}

char *protocol_build_status_request(const system_status_t *st,
				    const char *session_id,
				    long ts, const char *signature)
{
	struct json_object *root;
	const char *s;
	char *result;

	(void)session_id;	/* session_id 已在 URL path 中 */

	root = json_object_new_object();
	json_object_object_add(root, "cpu_temp",
		json_object_new_double(st->cpu_temp));
	json_object_object_add(root, "uptime",
		json_object_new_int64((int64_t)st->uptime));
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
	json_object_object_add(root, "ip",
		json_object_new_string(st->ip[0] ? st->ip : ""));

	/* 双向认证：时间戳 + 签名；证书链不重发，
	 * 服务器按 join 时缓存的设备公钥验签。 */
	if (signature && signature[0]) {
		json_object_object_add(root, "ts",
			json_object_new_int64(ts));
		jstr_add(root, "signature", signature);
	}

	s = json_object_to_json_string(root);
	result = strdup(s);
	json_object_put(root);

	return result;
}

/* ---- 响应解析 ---- */

/*
 * 解析时钟/时区字段（jdata 为 body 对象或响应根对象）。
 * 字段缺失时保持 0/空串，调用方据此判定是否下发。
 */
static void time_fields_parse(struct json_object *jdata, time_info_t *ti)
{
	struct json_object *jv, *jarr;
	size_t i, n;

	if (!jdata || !ti)
		return;

	if (json_object_object_get_ex(jdata, "server_time", &jv))
		ti->server_time = (long)json_object_get_int64(jv);
	if (json_object_object_get_ex(jdata, "tz_iana", &jv) &&
	    json_object_is_type(jv, json_type_string)) {
		snprintf(ti->tz_iana, sizeof(ti->tz_iana), "%s",
			 json_object_get_string(jv));
	}
	if (json_object_object_get_ex(jdata, "tz_posix", &jv) &&
	    json_object_is_type(jv, json_type_string)) {
		snprintf(ti->tz_posix, sizeof(ti->tz_posix), "%s",
			 json_object_get_string(jv));
	}
	if (!json_object_object_get_ex(jdata, "ntp_servers", &jarr) ||
	    !json_object_is_type(jarr, json_type_array))
		return;

	n = json_object_array_length(jarr);
	for (i = 0; i < n; i++) {
		struct json_object *je = json_object_array_get_idx(jarr, i);
		const char *s;
		size_t cur;

		if (!json_object_is_type(je, json_type_string))
			continue;
		s = json_object_get_string(je);
		if (!s || !s[0])
			continue;

		cur = strlen(ti->ntp_servers);
		if (cur >= sizeof(ti->ntp_servers) - 1)
			break;
		if (cur > 0)
			ti->ntp_servers[cur++] = ' ';
		snprintf(ti->ntp_servers + cur,
			 sizeof(ti->ntp_servers) - cur, "%s", s);
	}
}

int protocol_parse_time_response(const char *body, time_info_t *ti)
{
	struct json_object *root, *jdata;

	if (!ti)
		return -1;
	memset(ti, 0, sizeof(*ti));

	root = json_tokener_parse(body ? body : "{}");
	if (!root) {
		log_err("time response: JSON parse error");
		return -1;
	}

	if (json_object_object_get_ex(root, "body", &jdata) &&
	    json_object_is_type(jdata, json_type_object))
		time_fields_parse(jdata, ti);
	else
		time_fields_parse(root, ti);

	json_object_put(root);
	return 0;
}

int protocol_parse_join_response(const char *body, join_response_t *resp,
				 int *code, char *msg, size_t msg_sz)
{
	struct json_object *root, *jcode, *jmsg, *jdata, *jsid, *jxfrpc;
	struct json_object *jaddr, *jport;

	*code = -1;
	if (msg && msg_sz)
		msg[0] = 0;
	memset(resp, 0, sizeof(*resp));
	resp->frpc_mode = 1;	/* 缺省启动 xfrpc */

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
		struct json_object *jcakey, *jmode, *jv;

		/* 时钟/时区（不参与签名原文） */
		time_fields_parse(jdata, &resp->time_info);

		if (json_object_object_get_ex(jdata, "frpc_mode", &jmode))
			resp->frpc_mode = json_object_get_int(jmode);
		if (json_object_object_get_ex(jdata, "session_id", &jsid)) {
			const char *s = json_object_get_string(jsid);
			snprintf(resp->session_id, sizeof(resp->session_id),
				 "%s", s ? s : "");
		}
		if (json_object_object_get_ex(jdata, "ca_pub_key", &jcakey)) {
			const char *s = json_object_get_string(jcakey);
			snprintf(resp->ca_pub_key, sizeof(resp->ca_pub_key),
				 "%s", s ? s : "");
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
				resp->xfrpc_server_port =
					json_object_get_int(jport);
		}

		/* 双向认证字段（服务器下发） */
		if (json_object_object_get_ex(jdata, "cert", &jv) &&
		    json_object_is_type(jv, json_type_string)) {
			snprintf(resp->server_cert,
				 sizeof(resp->server_cert), "%s",
				 json_object_get_string(jv));
		}
		if (json_object_object_get_ex(jdata, "nonce", &jv) &&
		    json_object_is_type(jv, json_type_string)) {
			snprintf(resp->nonce, sizeof(resp->nonce), "%s",
				 json_object_get_string(jv));
		}
		if (json_object_object_get_ex(jdata, "signature", &jv) &&
		    json_object_is_type(jv, json_type_string)) {
			snprintf(resp->signature, sizeof(resp->signature),
				 "%s", json_object_get_string(jv));
		}
		if (json_object_object_get_ex(jdata, "ts", &jv))
			resp->ts = json_object_get_int64(jv);

		/* 云端 RADIUS 对接参数（body.radius，可选下发）：
		 * 缺失时保持空/0，调用方按需跳过；字段名与
		 * local_config_http_api.md §4.2 可写字段一一对应。 */
		if (json_object_object_get_ex(jdata, "radius", &jv) &&
		    json_object_is_type(jv, json_type_object)) {
			struct json_object *jr;

			if (json_object_object_get_ex(jv, "auth_server", &jr) &&
			    json_object_is_type(jr, json_type_string)) {
				snprintf(resp->radius_auth_server,
					 sizeof(resp->radius_auth_server),
					 "%s", json_object_get_string(jr));
			}
			if (json_object_object_get_ex(jv, "acct_server", &jr) &&
			    json_object_is_type(jr, json_type_string)) {
				snprintf(resp->radius_acct_server,
					 sizeof(resp->radius_acct_server),
					 "%s", json_object_get_string(jr));
			}
			if (json_object_object_get_ex(jv, "nas_ip", &jr) &&
			    json_object_is_type(jr, json_type_string)) {
				snprintf(resp->radius_nas_ip,
					 sizeof(resp->radius_nas_ip),
					 "%s", json_object_get_string(jr));
			}
			if (json_object_object_get_ex(jv, "auth_secret", &jr) &&
			    json_object_is_type(jr, json_type_string)) {
				snprintf(resp->radius_auth_secret,
					 sizeof(resp->radius_auth_secret),
					 "%s", json_object_get_string(jr));
			}
			if (json_object_object_get_ex(jv, "acct_secret", &jr) &&
			    json_object_is_type(jr, json_type_string)) {
				snprintf(resp->radius_acct_secret,
					 sizeof(resp->radius_acct_secret),
					 "%s", json_object_get_string(jr));
			}
			if (json_object_object_get_ex(jv, "auth_port", &jr))
				resp->radius_auth_port =
					json_object_get_int(jr);
			if (json_object_object_get_ex(jv, "acct_port", &jr))
				resp->radius_acct_port =
					json_object_get_int(jr);
			if (json_object_object_get_ex(jv, "tenant_org_id", &jr) &&
			    json_object_is_type(jr, json_type_string)) {
				snprintf(resp->tenant_org_id,
					 sizeof(resp->tenant_org_id),
					 "%s", json_object_get_string(jr));
			}

			log_debug("join response: radius auth=%s:%d "
				  "acct=%s:%d nas=%s "
				  "auth_secret=%s acct_secret=%s "
				  "tenant_org_id=%s",
				  resp->radius_auth_server,
				  resp->radius_auth_port,
				  resp->radius_acct_server,
				  resp->radius_acct_port,
				  resp->radius_nas_ip,
				  resp->radius_auth_secret[0] ? "***" : "",
				  resp->radius_acct_secret[0] ? "***" : "",
				  resp->tenant_org_id);
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
				   char *msg, size_t msg_sz,
				   long *srv_ts,
				   char *signature, size_t sig_sz,
				   time_info_t *ti)
{
	struct json_object *root, *jcode, *jmsg, *jv, *jdata;

	*code = -1;
	if (msg && msg_sz)
		msg[0] = 0;
	if (srv_ts)
		*srv_ts = 0;
	if (signature && sig_sz)
		signature[0] = 0;
	if (ti)
		memset(ti, 0, sizeof(*ti));

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
	if (srv_ts && json_object_object_get_ex(root, "ts", &jv))
		*srv_ts = json_object_get_int64(jv);
	if (signature && json_object_object_get_ex(root, "signature", &jv) &&
	    json_object_is_type(jv, json_type_string)) {
		snprintf(signature, sig_sz, "%s",
			 json_object_get_string(jv));
	}
	/* 时钟/时区（body 内，不参与签名原文） */
	if (ti && json_object_object_get_ex(root, "body", &jdata) &&
	    json_object_is_type(jdata, json_type_object))
		time_fields_parse(jdata, ti);

	json_object_put(root);
	return 0;
}
