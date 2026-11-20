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
#include "auth_remote.h"
#include "instance.h"		/* g_terminate_requested */
#include "skey.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <curl/curl.h>
#include <json-c/json.h>

/* 根 CA 信任锚与认证时间戳窗口（与 join/status 一致） */
#define CA_PEM_PATH		"/etc/skey/ca.pem"
#define AUTH_TS_WINDOW		300	/* 秒 */

struct resp_buf {
	char	*data;
	size_t	size;
};

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userp)
{
	struct resp_buf *buf = userp;
	size_t total = size * nmemb;
	char *tmp = realloc(buf->data, buf->size + total + 1);

	if (!tmp)
		return 0;
	buf->data = tmp;
	memcpy(buf->data + buf->size, ptr, total);
	buf->size += total;
	buf->data[buf->size] = 0;
	return total;
}

static void resp_buf_free(struct resp_buf *buf)
{
	free(buf->data);
	buf->data = NULL;
	buf->size = 0;
}

/* 终止信号到达时中止阻塞中的认证转发请求（与 http_client.c 同理，
 * 该请求在 libevent 回调栈中同步执行，不中止则 Ctrl+C 最长无响应 10s） */
static int xfer_abort_cb(void *clientp, curl_off_t dltotal, curl_off_t dlnow,
			 curl_off_t ultotal, curl_off_t ulnow)
{
	(void)clientp;
	(void)dltotal;
	(void)dlnow;
	(void)ultotal;
	(void)ulnow;
	return g_terminate_requested ? 1 : 0;
}

int auth_remote_authenticate(const xfrpc_config_t *cfg,
			     const device_info_t *dev,
			     const session_info_t *sess,
			     const char *username,
			     const char *password,
			     const char *user_creds,
			     auth_remote_result_t *result)
{
	char url[512];
	CURL *curl;
	CURLcode rc;
	long http_code = 0;
	struct resp_buf rbuf = { 0 };
	struct json_object *root, *jbody, *jcode, *jmsg;
	int ret = -1;
	int code = -1;
	long srv_ts = 0;		/* 服务器响应时间戳 */
	const char *sig_str = NULL;	/* 服务器响应签名（指向 root，勿 free） */

	memset(result, 0, sizeof(*result));

	/* 构造 URL */
	snprintf(url, sizeof(url), "%s://%s:%d%s",
		 protocol_str(cfg->auth_remote_proto),
		 cfg->auth_remote_host,
		 cfg->auth_remote_port,
		 cfg->auth_remote_path);

	/* 构造请求 JSON body */
	root = json_object_new_object();

	/* device_id 直接取自 skey 分区，不含 MAC 后缀 */
	json_object_object_add(root, "device_id",
		json_object_new_string(dev->device_id[0] ? dev->device_id : ""));

	json_object_object_add(root, "mac",
		json_object_new_string(dev->mac));
	json_object_object_add(root, "session_id",
		json_object_new_string(sess->session_id));
	if (username && username[0]) {
		json_object_object_add(root, "username",
			json_object_new_string(username));
	}
	if (password && password[0]) {
		json_object_object_add(root, "password",
			json_object_new_string(password));
	}
	if (user_creds && user_creds[0]) {
		json_object_object_add(root, "credentials",
			json_object_new_string(user_creds));
	}

	/* 双向认证（方案 D 公钥钉扎）：时间戳 + 设备签名（签名原文绑定
	 * session 与凭证哈希，私钥不出 pid 分区；设备公钥在 join 时已由
	 * 服务器钉扎缓存，不随请求重发）。
	 * 签名材料构造失败则 fail-closed，不发送未认证请求。 */
	{
		long ts = (long)time(NULL);
		char canon[1024];
		char sig[SKEY_SIG_LEN];

		memset(sig, 0, sizeof(sig));
		if (protocol_canon_auth_req(sess->session_id, ts,
				(username && username[0]) ? username : NULL,
				(password && password[0]) ? password : NULL,
				(user_creds && user_creds[0]) ?
					user_creds : NULL,
				canon, sizeof(canon)) < 0 ||
		    skey_sign_data(canon, sig, sizeof(sig)) < 0) {
			log_err("auth remote: sign request failed, aborting");
			json_object_put(root);
			return -1;
		}
		json_object_object_add(root, "ts",
			json_object_new_int64(ts));
		json_object_object_add(root, "signature",
			json_object_new_string(sig));
	}

	const char *body = json_object_to_json_string(root);

	/* 发送前日志：完整 URL + 请求体（INFO 级别，便于排查） */
	log_info("auth remote: -> POST %s (timeout=%ds, body=%s)",
		 url, cfg->auth_remote_timeout, body);

	/* 发送请求 */
	curl = curl_easy_init();
	if (!curl) {
		json_object_put(root);
		log_err("auth remote: curl_easy_init failed");
		return -1;
	}

	struct curl_slist *hdrs = NULL;
	hdrs = curl_slist_append(hdrs, "Content-Type: application/json");

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT,
			 (long)cfg->auth_remote_timeout);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,
			 (long)cfg->auth_remote_timeout);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rbuf);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	/* 支持终止信号秒级中止（与 join/status 通道一致） */
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
	curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, xfer_abort_cb);

	/* 以随固件发布的根 CA 校验服务器 TLS 证书。
	 * 该通道传输用户密码，校验失败 curl 直接报错（fail-closed）。
	 * 不做主机名绑定（与应用层信任模型一致，支持按 IP 部署）。 */
	curl_easy_setopt(curl, CURLOPT_CAINFO, CA_PEM_PATH);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	rc = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	curl_slist_free_all(hdrs);
	curl_easy_cleanup(curl);
	json_object_put(root);

	/* 终止信号主动中止：按失败返回，self-pipe 事件随即走正常退出，
	 * 不作为错误打印（避免退出时刷误导性 error 日志） */
	if (rc == CURLE_ABORTED_BY_CALLBACK) {
		log_info("auth remote: <- aborted by termination signal");
		resp_buf_free(&rbuf);
		return -1;
	}

	/* 接收后日志：HTTP 状态码 + 响应体长度/内容 */
	if (rc != CURLE_OK) {
		log_err("auth remote: <- curl error=%s (http_code=%ld, "
			"resp_len=%zu)",
			curl_easy_strerror(rc), http_code, rbuf.size);
		if (rbuf.size > 0) {
			log_err("auth remote: <- response body (first 512B): "
				"%.*s",
				(int)(rbuf.size > 512 ? 512 : rbuf.size),
				rbuf.data);
		}
		resp_buf_free(&rbuf);
		return -1;
	}

	log_info("auth remote: <- HTTP %ld, resp_len=%zu",
		 http_code, rbuf.size);

	if (http_code < 200 || http_code >= 300) {
		log_warn("auth remote: <- non-2xx http_code=%ld, "
			 "resp(%.256s)",
			 http_code, rbuf.data ? rbuf.data : "(empty)");
		resp_buf_free(&rbuf);
		return -1;
	}

	/* 解析响应 */
	root = json_tokener_parse(rbuf.data ? rbuf.data : "{}");
	resp_buf_free(&rbuf);
	if (!root) {
		log_err("auth remote: parse response json failed");
		return -1;
	}

	/* INFO 级别打印完整响应，便于排查 */
	log_info("auth remote: <- response json: %s",
		 json_object_to_json_string(root));

	if (json_object_object_get_ex(root, "error_code", &jcode)) {
		code = json_object_get_int(jcode);

		/* 提取服务器签名材料（顶层 ts/signature） */
		{
			struct json_object *jts, *jsig;

			if (json_object_object_get_ex(root, "ts", &jts))
				srv_ts = json_object_get_int64(jts);
			if (json_object_object_get_ex(root, "signature",
						      &jsig) &&
			    json_object_is_type(jsig, json_type_string))
				sig_str = json_object_get_string(jsig);
		}

		if (code < 0) {
			/* 业务错误 */
			if (json_object_object_get_ex(root, "msg", &jmsg))
				snprintf(result->reason,
					 sizeof(result->reason), "%s",
					 json_object_get_string(jmsg));
			else
				snprintf(result->reason,
					 sizeof(result->reason), "%s",
					 "remote auth error");
			result->approved = 0;
			ret = 0;	/* 通信成功，认证拒绝 */
			log_warn("auth remote: business reject error_code=%d "
				 "msg=%s", code, result->reason);
		} else if (code == 0) {
			/* 成功 */
			if (json_object_object_get_ex(root, "body", &jbody)) {
				struct json_object *japproved;
				if (json_object_object_get_ex(jbody,
							      "approved",
							      &japproved)) {
					result->approved =
						json_object_get_boolean(
							japproved);
				} else {
					result->approved = 1;
				}
				struct json_object *jreason;
				if (json_object_object_get_ex(jbody,
							      "reason",
							      &jreason)) {
					snprintf(result->reason,
						 sizeof(result->reason),
						 "%s",
						 json_object_get_string(jreason));
				}
				/* 提取认证服务器下发的 token */
				struct json_object *jtoken;
				if (json_object_object_get_ex(jbody,
							      "token",
							      &jtoken) &&
				    !json_object_is_type(jtoken,
							 json_type_null)) {
					snprintf(result->token,
						 sizeof(result->token), "%s",
						 json_object_get_string(jtoken));
				} else {
					log_warn("auth remote: body.token "
						 "missing or null");
				}
				/* 提取认证通过的用户名 */
				struct json_object *juser;
				if (json_object_object_get_ex(jbody,
							      "username",
							      &juser) &&
				    !json_object_is_type(juser,
							 json_type_null)) {
					snprintf(result->username,
						 sizeof(result->username),
						 "%s",
						 json_object_get_string(juser));
				}
				/* 提取用户邮箱（可选） */
				struct json_object *jemail;
				if (json_object_object_get_ex(jbody,
							      "email",
							      &jemail) &&
				    !json_object_is_type(jemail,
							 json_type_null)) {
					snprintf(result->email,
						 sizeof(result->email), "%s",
						 json_object_get_string(jemail));
				}
			} else {
				log_warn("auth remote: error_code=0 but body "
					 "missing, default approved=1");
				result->approved = 1;
			}
			ret = 0;
			log_info("auth remote: final %s (approved=%d, "
				 "token_len=%zu, user=%s, email=%s)",
				 result->approved ? "APPROVED" : "DENIED",
				 result->approved,
				 strlen(result->token),
				 result->username[0] ? result->username
						     : "(empty)",
				 result->email[0] ? result->email
						  : "(empty)");
		}
	} else {
		log_err("auth remote: response missing 'error_code' field");
	}

	/* 验签服务器响应（仅通信成功且业务通过时）：
	 * 用 join 时缓存的服务器证书链锚定根 CA 验签，
	 * 防止 token/用户名等响应字段被 MITM 篡改。 */
	if (ret == 0 && code == 0) {
		long now = (long)time(NULL);
		char canon[1024];

		if (!sess->server_cert[0] || !sig_str || srv_ts <= 0) {
			log_err("auth remote: response missing cert/ts/signature "
				"(server not mutually authenticated?)");
			ret = -1;
		} else if (now - srv_ts > AUTH_TS_WINDOW ||
			   srv_ts - now > AUTH_TS_WINDOW) {
			log_warn("auth remote: server ts out of window "
				 "(local=%ld srv=%ld, check NTP/clock)",
				 now, srv_ts);
			ret = -1;
		} else if (protocol_canon_auth_resp(sess->session_id,
				srv_ts, code, canon, sizeof(canon)) < 0 ||
			   skey_verify_peer(canon, sig_str,
				sess->server_cert) < 0) {
			log_err("auth remote: server signature verify failed "
				"(untrusted/expired/MITM?)");
			ret = -1;
		} else {
			log_info("auth remote: server identity verified "
				 "(CA chain + signature)");
		}
	}

	json_object_put(root);
	return ret;
}
