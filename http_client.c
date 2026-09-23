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
#include "http_client.h"
#include "log.h"

#include <curl/curl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

/* ---- 响应缓冲区 ---- */

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

/* ---- URL 构造 ---- */

static void build_server_url(const xfrpc_config_t *cfg, char *buf, size_t sz,
			     const char *path)
{
	const char *host = cfg->server_name[0] ? cfg->server_name :
			   cfg->server_ip;
	const char *scheme = (cfg->protocol == PROTO_HTTPS) ? "https" : "http";

	snprintf(buf, sz, "%s://%s:%d%s", scheme, host,
		 cfg->server_port, path);
}

/* ---- HTTP POST ---- */

/*
 * 同步 POST。
 * 返回 0 成功，-ETIMEDOUT 超时，-EIO 其他错误。
 */
static int http_post(const char *url, const char *body, int timeout_sec,
		     struct resp_buf *resp)
{
	CURL *curl;
	CURLcode rc;
	struct curl_slist *hdrs;
	long http_code = 0;
	int ret = 0;

	curl = curl_easy_init();
	if (!curl)
		return -ENOMEM;

	hdrs = curl_slist_append(NULL, "Content-Type: application/json");

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)timeout_sec);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long)timeout_sec);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
	/* HTTPS 跳过证书校验（服务端可能使用自签名证书） */
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	rc = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

	curl_slist_free_all(hdrs);
	curl_easy_cleanup(curl);

	if (rc == CURLE_OPERATION_TIMEDOUT)
		return -ETIMEDOUT;
	if (rc != CURLE_OK) {
		log_err("curl error: %s", curl_easy_strerror(rc));
		return -EIO;
	}
	if (http_code < 200 || http_code >= 300) {
		log_warn("http %s returned status %ld", url, http_code);
		return -EIO;
	}

	return ret;
}

/* ---- 高层接口 ---- */

int http_join(const xfrpc_config_t *cfg, const device_info_t *dev,
	      join_response_t *resp, int timeout_sec)
{
	char url[512];
	char *body;
	struct resp_buf rbuf = { 0 };
	int ret, code;
	char msg[256] = { 0 };

	build_server_url(cfg, url, sizeof(url), "/api/v1/join");

	body = protocol_build_join_request(dev);
	if (!body) {
		log_err("failed to build join request");
		return -ENOMEM;
	}

	log_info("sending join request to %s", url);
	ret = http_post(url, body, timeout_sec, &rbuf);
	free(body);

	if (ret == -ETIMEDOUT) {
		resp_buf_free(&rbuf);
		return -ETIMEDOUT;
	}
	if (ret < 0) {
		resp_buf_free(&rbuf);
		return ret;
	}

	log_info("join response JSON:\n%s", rbuf.data ? rbuf.data : "(empty)");

	/* 解析响应 */
	ret = protocol_parse_join_response(rbuf.data ? rbuf.data : "{}",
					   resp, &code, msg, sizeof(msg));
	resp_buf_free(&rbuf);

	if (ret < 0)
		return -EIO;		/* JSON 解析失败 */
	if (code < 0) {
		log_warn("join rejected: error_code=%d msg=%s", code, msg);
		if (code == -1001 || code == -1002)
			return -EACCES;		/* 服务端拒绝加入，退避后重试 */
		return -EAGAIN;		/* 可重试：参数错误/限频/内部错误 */
	}

	return 0;
}

int http_status(const xfrpc_config_t *cfg, const session_info_t *sess,
		const system_status_t *st, int timeout_sec)
{
	char url[512];
	char path[256];
	char *body;
	struct resp_buf rbuf = { 0 };
	int ret, code;
	char msg[256] = { 0 };

	snprintf(path, sizeof(path), "/api/v1/status/%s", sess->session_id);
	build_server_url(cfg, url, sizeof(url), path);

	body = protocol_build_status_request(st);
	if (!body) {
		log_err("failed to build status request");
		return -ENOMEM;
	}

	log_debug("sending status request to %s", url);
	ret = http_post(url, body, timeout_sec, &rbuf);
	free(body);

	if (ret == -ETIMEDOUT) {
		resp_buf_free(&rbuf);
		return -ETIMEDOUT;
	}
	if (ret < 0) {
		resp_buf_free(&rbuf);
		return ret;
	}

	ret = protocol_parse_status_response(rbuf.data ? rbuf.data : "{}",
					     &code, msg, sizeof(msg));
	resp_buf_free(&rbuf);

	if (ret < 0)
		return -EIO;
	if (code < 0) {
		log_warn("status rejected: error_code=%d msg=%s", code, msg);
		return -EIO;		/* 所有状态失败都触发重新 join */
	}

	return 0;
}
