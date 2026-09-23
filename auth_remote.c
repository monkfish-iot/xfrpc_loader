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
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <json-c/json.h>

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

	/* HTTPS 跳过证书校验（与 join/status 一致） */
	if (cfg->auth_remote_proto == PROTO_HTTPS) {
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		log_info("auth remote: HTTPS mode (peer/host verify disabled)");
	}

	rc = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	curl_slist_free_all(hdrs);
	curl_easy_cleanup(curl);
	json_object_put(root);

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
		int code = json_object_get_int(jcode);

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

	json_object_put(root);
	return ret;
}
