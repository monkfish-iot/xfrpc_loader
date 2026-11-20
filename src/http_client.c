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
#include "instance.h"		/* g_terminate_requested */
#include "skey.h"
#include "time_sync.h"
#include "log.h"

#include <curl/curl.h>
#include <json-c/json.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>

/* 根 CA 信任锚（随固件发布），双向认证时间戳窗口 */
#define CA_PEM_PATH		"/etc/skey/ca.pem"
#define AUTH_TS_WINDOW		300	/* 秒 */

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

/*
 * 传输进度回调（libcurl 在连接/传输等待期间约每秒调用一次，
 * 即使尚无数据收发也会调用）。终止标志置位时返回非 0，
 * curl_easy_perform 立即以 CURLE_ABORTED_BY_CALLBACK 返回，
 * 使阻塞中的 join/status 请求可被 Ctrl+C 秒级打断。
 */
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
 * 同步 HTTP 请求。
 * body 非 NULL 时 POST JSON，为 NULL 时 GET。
 * insecure 非 0 时关闭服务器证书校验（仅用于时钟引导 /api/v1/time）。
 * 返回 0 成功，-ETIMEDOUT 超时，-EINTR 终止信号中止，
 * -EACCES TLS 对端校验失败，-EIO 其他错误。
 */
static int http_request(const char *url, const char *body, int insecure,
			int timeout_sec, struct resp_buf *resp)
{
	CURL *curl;
	CURLcode rc;
	struct curl_slist *hdrs = NULL;
	long http_code = 0;
	int ret = 0;

	curl = curl_easy_init();
	if (!curl)
		return -ENOMEM;

	if (body) {
		hdrs = curl_slist_append(NULL, "Content-Type: application/json");
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
	} else {
		curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
	}

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)timeout_sec);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long)timeout_sec);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
	/* 开启进度回调以支持终止信号秒级中止（NOSIGNAL 下唯一的中断点） */
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
	curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, xfer_abort_cb);
	/* 以随固件发布的根 CA 校验服务器 TLS 证书（fail-closed）。
	 * 不做主机名绑定（与应用层信任模型一致，支持按 IP 部署）。
	 * 本机回环地址（127.0.0.1，如 webauthd 本地配置接口）明文 HTTP，
	 * 不受影响。 */
	curl_easy_setopt(curl, CURLOPT_CAINFO, CA_PEM_PATH);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, insecure ? 0L : 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	rc = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

	curl_slist_free_all(hdrs);
	curl_easy_cleanup(curl);

	if (rc == CURLE_OPERATION_TIMEDOUT)
		return -ETIMEDOUT;
	if (rc == CURLE_ABORTED_BY_CALLBACK) {
		/* 收到 SIGINT/SIGTERM，进度回调主动中止；
		* self-pipe 事件随即派发 EV_SIGTERM 走正常退出 */
		log_info("http request aborted by termination signal");
		return -EINTR;
	}
	/* 证书链不受信/过期/吊销：疑似 MITM 或服务器证书问题，致命处理 */
	if (rc == CURLE_PEER_FAILED_VERIFICATION ||
	    rc == CURLE_SSL_CACERT ||
	    rc == CURLE_SSL_CERTPROBLEM ||
	    rc == CURLE_SSL_CIPHER) {
		log_err("curl TLS peer verification failed: %s",
			curl_easy_strerror(rc));
		return -EACCES;
	}
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

static int http_post(const char *url, const char *body, int timeout_sec,
		     struct resp_buf *resp)
{
	return http_request(url, body, 0, timeout_sec, resp);
}

/*
 * 时钟引导：本机时钟严重偏差（如出厂未对时）会导致服务器证书
 * NotBefore 校验失败、TLS 握手被拒。此时以不校验证书的方式请求
 * 免鉴权接口 /api/v1/time，取回服务器时间并校正本机时钟与
 * 时区/NTP 配置。仅在 join 因 TLS 校验失败时调用一次。
 * 返回 0 成功，负值失败（语义同 http_request）。
 */
static int http_fetch_time_insecure(const xfrpc_config_t *cfg, int timeout_sec)
{
	char url[512];
	struct resp_buf rbuf = { 0 };
	time_info_t ti;
	int ret;

	build_server_url(cfg, url, sizeof(url), "/api/v1/time");
	log_info("clock bootstrap: fetching server time from %s "
		 "(TLS verify disabled)", url);

	ret = http_request(url, NULL, 1, timeout_sec, &rbuf);
	if (ret < 0) {
		resp_buf_free(&rbuf);
		return ret;
	}

	if (protocol_parse_time_response(rbuf.data ? rbuf.data : "{}",
					 &ti) < 0) {
		resp_buf_free(&rbuf);
		return -EIO;
	}
	resp_buf_free(&rbuf);

	if (ti.server_time <= 0) {
		log_warn("clock bootstrap: response missing server_time");
		return -EIO;
	}

	time_sync_apply(cfg, &ti);
	log_info("clock bootstrap: applied server_time=%ld tz=%s/%s",
		 ti.server_time, ti.tz_iana, ti.tz_posix);
	return 0;
}

/* ---- 高层接口 ---- */

/*
 * 构造 join 请求的双向认证材料（方案 D 公钥钉扎）：
 *   生成 nonce、对 canonical 文本（含 device_id/pubkey 摘要/nonce/ts）
 *   做设备私钥签名。设备公钥随请求体 pub_key 字段上报，服务器首次
 *   join 钉扎公钥，后续凭缓存公钥验签；设备不出示证书链。
 * 返回 0 成功，-1 失败。
 */
static int join_build_auth(const device_info_t *dev, join_auth_t *auth,
			   char *nonce, size_t nonce_sz,
			   char *sig, size_t sig_sz)
{
	char canon[1024];

	memset(auth, 0, sizeof(*auth));

	if (skey_gen_nonce(nonce, nonce_sz) < 0)
		return -1;

	auth->nonce = nonce;
	auth->ts = (long)time(NULL);
	auth->signature = sig;

	if (protocol_canon_join_req(dev, nonce, auth->ts,
				    canon, sizeof(canon)) < 0)
		return -1;
	if (skey_sign_data(canon, sig, sig_sz) < 0)
		return -1;
	return 0;
}

/*
 * 验证 join 响应的服务器身份：
 *   nonce 回显一致、时间戳在窗口内、证书链锚定根 CA 且签名有效。
 * 返回 0 通过；-EACCES 致命（链不受信/签名不符/nonce 不符）；
 * -EAGAIN 可重试（时间戳越界，多为本机时钟未同步）。
 */
static int join_verify_response(const device_info_t *dev,
				const join_response_t *resp,
				const char *req_nonce)
{
	char canon[1024];
	long now = (long)time(NULL);

	if (!resp->server_cert[0] || !resp->signature[0] ||
	    !resp->nonce[0]) {
		log_err("join auth: response missing cert/nonce/signature");
		return -EACCES;
	}
	if (strcmp(resp->nonce, req_nonce) != 0) {
		log_err("join auth: nonce echo mismatch (possible replay)");
		return -EACCES;
	}
	if (resp->ts <= 0 || now - resp->ts > AUTH_TS_WINDOW ||
	    resp->ts - now > AUTH_TS_WINDOW) {
		log_warn("join auth: server ts out of window (local=%ld "
			 "srv=%ld, check NTP/clock)", now, resp->ts);
		return -EAGAIN;
	}
	if (protocol_canon_join_resp(dev->device_id, resp,
				     canon, sizeof(canon)) < 0) {
		log_err("join auth: canonical text build failed");
		return -EACCES;
	}
	if (skey_verify_peer(canon, resp->signature,
			     resp->server_cert) < 0) {
		log_err("join auth: server chain/signature verify failed "
			"(untrusted/expired/MITM?)");
		return -EACCES;
	}

	log_info("join auth: server identity verified (CA chain + signature)");
	return 0;
}

int http_join(const xfrpc_config_t *cfg, const device_info_t *dev,
	      join_response_t *resp, int timeout_sec)
{
	char url[512];
	char *body;
	struct resp_buf rbuf;
	int ret, code, attempt;
	char msg[256] = { 0 };
	join_auth_t auth;
	char nonce[SKEY_NONCE_B64_LEN] = { 0 };
	char sig[SKEY_SIG_LEN];

	build_server_url(cfg, url, sizeof(url), "/api/v1/join");

	/*
	 * 最多尝试两次：首次因 TLS 证书校验失败（多为本机时钟未对时，
	 * 证书 NotBefore 未生效）或服务端以 -1003（时间戳越窗）拒绝时，
	 * 用免鉴权 /api/v1/time 引导校正时钟后立即重试一次；仍失败则
	 * 按原错误返回，避免无限循环。每次尝试重新生成 nonce/ts/签名
	 * （校正时钟后时间戳需重建）。
	 */
	for (attempt = 0; attempt < 2; attempt++) {
		memset(&rbuf, 0, sizeof(rbuf));
		memset(nonce, 0, sizeof(nonce));
		msg[0] = 0;
		code = -1;

		if (join_build_auth(dev, &auth, nonce, sizeof(nonce),
				    sig, sizeof(sig)) < 0) {
			log_err("join: failed to build mutual-auth materials");
			return -EIO;
		}
		body = protocol_build_join_request(dev, &auth);
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
		if (ret == -EACCES) {
			/* 时钟引导一次；失败则按致命 TLS 错误返回 */
			resp_buf_free(&rbuf);
			if (attempt == 0 &&
			    http_fetch_time_insecure(cfg, timeout_sec) == 0) {
				log_info("clock bootstrap ok, retrying join");
				continue;
			}
			log_warn("clock bootstrap failed, join stays rejected");
			return -EACCES;
		}
		if (ret < 0) {
			resp_buf_free(&rbuf);
			return ret;
		}

		log_info("join response JSON:\n%s",
			 rbuf.data ? rbuf.data : "(empty)");

		ret = protocol_parse_join_response(rbuf.data ? rbuf.data : "{}",
						   resp, &code, msg,
						   sizeof(msg));
		resp_buf_free(&rbuf);
		if (ret < 0)
			return -EIO;	/* JSON 解析失败 */

		/* -1003：签名/时间戳无效（常见于本机时钟偏差），引导后重试 */
		if (code == -1003 && attempt == 0) {
			if (http_fetch_time_insecure(cfg, timeout_sec) == 0) {
				log_info("clock bootstrap (-1003) ok, "
					 "retrying join");
				continue;
			}
			log_warn("clock bootstrap failed on -1003");
			return -EAGAIN;
		}
		break;
	}

	if (code < 0) {
		log_warn("join rejected: error_code=%d msg=%s", code, msg);
		/* -1001 在服务端同时承载"未授权"与 join IP "rate limit"，
		 * -1002 为禁用；返回值仅区分日志级别（FATAL/FAIL），
		 * 状态机对两者统一退避重试、常驻不退出（fail-closed：
		 * 验签不过不进 RUNNING） */
		if (code == -1001 || code == -1002)
			return -EACCES;
		return -EAGAIN;		/* 签名/时间戳无效(-1003)、
					 * 参数错误/内部错误 */
	}

	/* 业务成功：验证服务器身份（证书链锚定根 CA + nonce 回显 + 签名） */
	ret = join_verify_response(dev, resp, nonce);
	if (ret != 0) {
		/* 服务端时间戳越窗多为本机时钟偏差：TLS 已校验通过，
		 * 可信任响应中的 server_time，先校正，下次 join 即可通过 */
		if (ret == -EAGAIN)
			time_sync_apply(cfg, &resp->time_info);
		return ret;		/* -EACCES 致命 / -EAGAIN 可重试 */
	}

	/* 应用服务器下发的时钟/时区/NTP 配置（不参与签名校验） */
	time_sync_apply(cfg, &resp->time_info);

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
	char canon[1024];
	char sig_req[SKEY_SIG_LEN];
	char sig_resp[SKEY_SIG_LEN];
	long ts = (long)time(NULL);
	long srv_ts = 0;
	time_info_t ti;
	static long s_last_resp_ts;	/* 响应时间戳单调防重放 */
	long now;

	snprintf(path, sizeof(path), "/api/v1/status/%s", sess->session_id);
	build_server_url(cfg, url, sizeof(url), path);

	/* 请求加签：绑定 session_id 与时间戳（证书链不重发，
	 * 服务器按 join 时缓存的设备公钥验签） */
	memset(sig_req, 0, sizeof(sig_req));
	if (protocol_canon_status_req(sess->session_id, ts,
				      canon, sizeof(canon)) < 0 ||
	    skey_sign_data(canon, sig_req, sizeof(sig_req)) < 0) {
		log_err("status: sign request failed");
		return -EIO;
	}
	body = protocol_build_status_request(st, sess->session_id,
					     ts, sig_req);
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
					     &code, msg, sizeof(msg),
					     &srv_ts,
					     sig_resp, sizeof(sig_resp),
					     &ti);
	resp_buf_free(&rbuf);

	if (ret < 0)
		return -EIO;
	if (code < 0) {
		log_warn("status rejected: error_code=%d msg=%s", code, msg);
		return -EIO;		/* 所有状态失败都触发重新 join */
	}

	/* 验签服务器响应：证书链用 join 时缓存的服务器证书链 */
	now = (long)time(NULL);
	if (!sess->server_cert[0] || !sig_resp[0]) {
		log_err("status auth: response missing cert/signature "
			"(server not mutually authenticated?)");
		return -EIO;
	}
	if (srv_ts <= 0 || now - srv_ts > AUTH_TS_WINDOW ||
	    srv_ts - now > AUTH_TS_WINDOW) {
		log_warn("status auth: server ts out of window (local=%ld "
			 "srv=%ld, check NTP/clock)", now, srv_ts);
		return -EIO;
	}
	if (srv_ts <= s_last_resp_ts) {
		log_warn("status auth: response ts not monotonic "
			 "(possible replay)");
		return -EIO;
	}
	if (protocol_canon_status_resp(sess->session_id, srv_ts, code,
				       canon, sizeof(canon)) < 0 ||
	    skey_verify_peer(canon, sig_resp, sess->server_cert) < 0) {
		log_err("status auth: server signature verify failed "
			"(untrusted/expired/MITM?)");
		return -EIO;
	}
	s_last_resp_ts = srv_ts;

	/* 心跳成功：应用服务器下发的时钟/时区/NTP（不参与签名校验） */
	time_sync_apply(cfg, &ti);

	return 0;
}

/* ---- webauthd 本地配置接口（见 local_config_http_api.md） ---- */

/* 服务监听 127.0.0.1:60000，仅本机回环可达，无鉴权、明文 HTTP */
#define LOCAL_CFG_RADIUS_URL	"http://127.0.0.1:60000/v1/config/radius/update"

/* 接口 §4.2 字符串字段长度上限 */
#define RAD_API_MAX_SERVER	23	/* auth_server/acct_server */
#define RAD_API_MAX_NAS		31	/* nas_ip */
#define RAD_API_MAX_SECRET	31	/* auth_secret/acct_secret */
#define RAD_API_MAX_TENANT	63	/* tenant_org_id */

static int rad_valid_ipv4(const char *s)
{
	struct in_addr a;

	return s[0] && inet_pton(AF_INET, s, &a) == 1;
}

/*
 * 追加可选字符串字段。值为空表示云端未下发，跳过；超长或 IPv4 不合法时
 * 同样跳过并告警——接口为“全量校验、一票否决”，不能让一个坏字段导致
 * 整单被 -1000/-1002 拒绝。返回 1=已加入请求，0=跳过。
 */
static int rad_add_string(json_object *body, const char *key, const char *val,
			  size_t max_len, int need_ipv4)
{
	size_t n;

	if (!val[0])
		return 0;
	n = strlen(val);
	if (n > max_len) {
		log_warn("local config: skip field '%s': value too long "
			 "(%zu > %zu)", key, n, max_len);
		return 0;
	}
	if (need_ipv4 && !rad_valid_ipv4(val)) {
		log_warn("local config: skip field '%s': invalid IPv4 '%s'",
			 key, val);
		return 0;
	}
	json_object_object_add(body, key, json_object_new_string(val));
	return 1;
}

/* 追加可选端口字段；0 表示云端未下发，跳过；越界（非 1~65535）告警跳过 */
static void rad_add_port(json_object *body, const char *key, int port)
{
	if (port == 0)
		return;
	if (port < 1 || port > 65535) {
		log_warn("local config: skip field '%s': port %d out of range",
			 key, port);
		return;
	}
	json_object_object_add(body, key, json_object_new_int(port));
}

int http_local_radius_update(const session_info_t *sess, int timeout_sec)
{
	json_object *body;
	const char *jstr;
	struct resp_buf rbuf = { 0 };
	int ret;
	int n_fields;
	json_object *root, *jcode, *jmsg;
	int ec;
	const char *emsg = "";

	body = json_object_new_object();
	if (!body)
		return -ENOMEM;

	/* 仅加入云端实际下发且通过本地校验的字段（接口部分更新语义） */
	(void)rad_add_string(body, "auth_server", sess->radius_auth_server,
			     RAD_API_MAX_SERVER, 1);
	(void)rad_add_string(body, "acct_server", sess->radius_acct_server,
			     RAD_API_MAX_SERVER, 1);
	(void)rad_add_string(body, "nas_ip", sess->radius_nas_ip,
			     RAD_API_MAX_NAS, 1);
	(void)rad_add_string(body, "auth_secret", sess->radius_auth_secret,
			     RAD_API_MAX_SECRET, 0);
	(void)rad_add_string(body, "acct_secret", sess->radius_acct_secret,
			     RAD_API_MAX_SECRET, 0);
	rad_add_port(body, "auth_port", sess->radius_auth_port);
	rad_add_port(body, "acct_port", sess->radius_acct_port);
	(void)rad_add_string(body, "tenant_org_id", sess->tenant_org_id,
			     RAD_API_MAX_TENANT, 0);

	n_fields = json_object_object_length(body);
	if (n_fields == 0) {
		log_err("local config: no valid radius field to push "
			"(auth='%s' acct='%s')",
			sess->radius_auth_server, sess->radius_acct_server);
		json_object_put(body);
		return -EACCES;	/* 数据本身非法，重试无意义 */
	}

	jstr = json_object_to_json_string(body);

	log_info("pushing cloud radius config to webauthd local API: "
		 "auth=%s:%d acct=%s:%d nas=%s tenant=%s (%d field(s))",
		 sess->radius_auth_server[0] ? sess->radius_auth_server : "-",
		 sess->radius_auth_port,
		 sess->radius_acct_server[0] ? sess->radius_acct_server : "-",
		 sess->radius_acct_port,
		 sess->radius_nas_ip[0] ? sess->radius_nas_ip : "-",
		 sess->tenant_org_id[0] ? sess->tenant_org_id : "-",
		 n_fields);
	log_debug("local config: POST %s body=%s", LOCAL_CFG_RADIUS_URL, jstr);

	ret = http_post(LOCAL_CFG_RADIUS_URL, jstr, timeout_sec, &rbuf);
	if (ret == -EINTR)
		goto out;			/* 终止信号，进程退出中 */
	if (ret == -ETIMEDOUT) {
		log_warn("local config: request timed out after %ds",
			 timeout_sec);
		ret = -EAGAIN;
		goto out;
	}
	if (ret < 0) {
		/* 连接被拒（webauthd 未启动）等网络错误均按可重试处理 */
		log_warn("local config: request failed (ret=%d), "
			 "webauthd not ready?", ret);
		ret = -EAGAIN;
		goto out;
	}

	/* HTTP 恒为 200，业务成败看响应体 error_code */
	root = json_tokener_parse(rbuf.data ? rbuf.data : "");
	if (!root) {
		log_warn("local config: unparseable response: '%s'",
			 rbuf.data ? rbuf.data : "(empty)");
		ret = -EAGAIN;
		goto out;
	}
	if (!json_object_object_get_ex(root, "error_code", &jcode)) {
		log_warn("local config: response missing error_code: '%s'",
			 rbuf.data ? rbuf.data : "(empty)");
		json_object_put(root);
		ret = -EAGAIN;
		goto out;
	}
	ec = json_object_get_int(jcode);
	if (json_object_object_get_ex(root, "msg", &jmsg) &&
	    json_object_is_type(jmsg, json_type_string))
		emsg = json_object_get_string(jmsg);

	if (ec == 0) {
		log_info("cloud radius config applied by webauthd "
			 "(%d field(s))", n_fields);
		ret = 0;
	} else if (ec == -1004 || ec == -1006) {
		/* -1004 UCI 写盘失败：原样重试可补写；
		 * -1006 热更新失败已回退：按文档排查后重试 */
		log_warn("local config: temporary business error_code=%d "
			 "msg='%s', will retry", ec, emsg);
		ret = -EAGAIN;
	} else {
		/* -1000/-1001/-1002/-1003/-1005/-14 等校验类错误：
		 * 不会随重试自愈，避免无限重试刷日志 */
		log_err("local config: rejected error_code=%d msg='%s'",
			ec, emsg);
		ret = -EACCES;
	}
	json_object_put(root);

out:
	resp_buf_free(&rbuf);
	json_object_put(body);
	return ret;
}
