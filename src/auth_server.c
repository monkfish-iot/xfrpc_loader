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
#include "auth_server.h"
#include "auth_local.h"
#include "auth_remote.h"
#include "log.h"

#include <event2/buffer.h>
#include <string.h>
#include <stdlib.h>
#include <json-c/json.h>

/*
 * 认证请求处理流程（面向用户输入）：
 *   1. 接收用户输入的用户名/密码
 *      - GET: 从 Authorization: Basic 头解码（nginx auth_request 转发）
 *      - POST: 从 JSON body 解析 {"username":"...", "password":"..."}
 *   2. 检查 session 是否就绪（是否已 join）
 *   3. 补齐 device_id / mac / session_id，发往远程认证服务器
 *   4. 远程通过 → 读取 /etc/config/localpasswd 解密得到 LuCI 密码
 *      （文件不存在则用默认空密码）
 *   5. 用 root + 该密码登录 LuCI RPC，获取 session token
 *   6. 登录成功后生成 16 字符随机密码，加密保存到 /etc/config/localpasswd
 *   7. 返回远程 token + LuCI token + 用户信息给 nginx
 *   8. 远程拒绝 → 返回 401
 *   9. 通信失败 / 资源未就绪 → 返回 503
 */

/* ---- Base64 解码 ---- */

static const char b64_table[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_decode(const char *in, char *out, size_t out_sz)
{
	int val = 0, valb = -8;
	size_t i, outlen = 0;
	size_t inlen = strlen(in);

	for (i = 0; i < inlen; i++) {
		char c = in[i];
		const char *p;

		if (c == '=')
			break;
		p = strchr(b64_table, c);
		if (!p)
			continue;
		val = (val << 6) | (int)(p - b64_table);
		valb += 6;
		if (valb >= 0 && outlen < out_sz - 1) {
			out[outlen++] = (char)((val >> valb) & 0xFF);
			valb -= 8;
		}
	}
	out[outlen] = 0;
	return (int)outlen;
}

/* ---- Basic auth 解析 ---- */

/*
 * 解析 Authorization: Basic <base64> 头，提取用户名和密码。
 *   返回 0 成功，-1 非 Basic auth 或解析失败。
 */
static int parse_basic_auth(const char *auth_header,
			    char *username, size_t uname_sz,
			    char *password, size_t pwd_sz)
{
	char decoded[512];
	char *colon;

	if (!auth_header || strncmp(auth_header, "Basic ", 6) != 0)
		return -1;

	if (base64_decode(auth_header + 6, decoded, sizeof(decoded)) <= 0)
		return -1;

	colon = strchr(decoded, ':');
	if (!colon)
		return -1;

	*colon = 0;
	snprintf(username, uname_sz, "%.*s", (int)uname_sz - 1, decoded);
	snprintf(password, pwd_sz, "%.*s", (int)pwd_sz - 1, colon + 1);
	return 0;
}

/* ---- POST JSON body 解析 ---- */

/*
 * 从 POST 请求 body 解析 {"username":"...", "password":"..."}。
 *   返回 0 成功，-1 解析失败或缺少字段。
 */
static int parse_post_body(struct evhttp_request *req,
			   char *username, size_t uname_sz,
			   char *password, size_t pwd_sz)
{
	struct evbuffer *in_buf = evhttp_request_get_input_buffer(req);
	size_t body_len = evbuffer_get_length(in_buf);
	char *body;
	struct json_object *root, *jval;
	int ret = -1;

	if (body_len == 0 || body_len > 4096) {
		log_warn("auth: POST body length %zu invalid", body_len);
		return -1;
	}

	body = malloc(body_len + 1);
	if (!body)
		return -1;

	evbuffer_copyout(in_buf, body, body_len);
	body[body_len] = 0;

	root = json_tokener_parse(body);
	free(body);

	if (!root) {
		log_warn("auth: POST body json parse failed");
		return -1;
	}

	if (json_object_object_get_ex(root, "username", &jval) &&
	    json_object_is_type(jval, json_type_string)) {
		snprintf(username, uname_sz, "%s",
			 json_object_get_string(jval));
	}
	if (json_object_object_get_ex(root, "password", &jval) &&
	    json_object_is_type(jval, json_type_string)) {
		snprintf(password, pwd_sz, "%s",
			 json_object_get_string(jval));
	}

	if (username[0] || password[0])
		ret = 0;

	json_object_put(root);
	return ret;
}

/* ---- 发送 JSON 响应 ---- */

static void send_json_reply(struct evhttp_request *req, int code,
			    const char *status, const char *json_body)
{
	struct evbuffer *buf = evbuffer_new();
	evbuffer_add_printf(buf, "%s", json_body);
	evhttp_add_header(evhttp_request_get_output_headers(req),
			 "Content-Type", "application/json");
	evhttp_send_reply(req, code, status, buf);
	evbuffer_free(buf);
}

/* ---- 获取本地 LuCI 密码 ---- */

/*
 * GET /api/password
 * 仅监听 127.0.0.1，返回当前 LuCI root 明文密码（JSON）。
 *   供本地运维脚本（show_luci_passwd.sh）调用，避免在 shell 里
 *   直接用 openssl 命令行解密（依赖/密钥不匹配问题多）。
 * 响应：{"password":"<明文>"}  或  {"error":"<原因>"}
 */
static void handle_get_password(struct evhttp_request *req, void *arg)
{
	auth_server_ctx_t *ctx = arg;
	enum evhttp_cmd_type method = evhttp_request_get_command(req);
	char password[64] = { 0 };
	char body[128];
	int reason = AUTH_LPWD_OK;

	(void)ctx;

	if (method != EVHTTP_REQ_GET) {
		send_json_reply(req, 405, "Method Not Allowed",
				"{\"error\":\"GET only\"}");
		return;
	}

	if (auth_local_get_password_ex(password, sizeof(password),
				       &reason) < 0) {
		log_warn("api/password: get local password failed");
		send_json_reply(req, 500, "Internal Server Error",
				"{\"error\":\"local password unavailable\"}");
		return;
	}
	/* auth_local_get_password_ex 在文件缺失/解密失败时回退为空串但不报错；
	 * 此处显式检查空密码，并按 reason 区分两种原因，让运维工具
	 * （show_luci_passwd.sh）能直接看到失败根因。 */
	if (password[0] == 0) {
		if (reason == AUTH_LPWD_NOT_INIT) {
			log_warn("api/password: local password not initialized "
				 "(%s missing)", LOCALPASSWD_FILE);
			send_json_reply(req, 404, "Not Found",
				"{\"error\":\"local password not initialized; "
				"use default root password\"}");
		} else {
			log_warn("api/password: decrypt failed (skey mismatch or "
				 "corrupted %s)", LOCALPASSWD_FILE);
			send_json_reply(req, 500, "Internal Server Error",
				"{\"error\":\"local password decrypt failed: skey "
				"mismatch or corrupted localpasswd\"}");
		}
		return;
	}

	snprintf(body, sizeof(body), "{\"password\":\"%s\"}", password);
	send_json_reply(req, 200, "OK", body);
	log_info("api/password: password retrieved (len=%zu)",
		 strlen(password));
}

/* ---- 主处理函数 ---- */

static void handle_auth_request(struct evhttp_request *req, void *arg)
{
	auth_server_ctx_t *ctx = arg;
	enum evhttp_cmd_type method = evhttp_request_get_command(req);
	struct evkeyvalq *in_hdrs = evhttp_request_get_input_headers(req);
	const char *auth_header = NULL;
	const char *remote_addr;
	char username[64] = { 0 };
	char password[128] = { 0 };
	auth_remote_result_t result;
	luci_token_t luci_token;
	char luci_password[64] = { 0 };
	int rc;

	/* 接受 GET（nginx auth_request）和 POST（直接用户输入） */
	if (method != EVHTTP_REQ_GET && method != EVHTTP_REQ_POST) {
		evhttp_send_error(req, 405, "Method Not Allowed");
		return;
	}

	remote_addr = evhttp_find_header(in_hdrs, "X-Real-IP");
	if (!remote_addr)
		remote_addr = "-";

	/* 步骤 1: 提取用户名/密码 */
	if (method == EVHTTP_REQ_GET) {
		/* GET: 从 Basic auth 头解码（nginx 转发） */
		auth_header = evhttp_find_header(in_hdrs, "Authorization");
		log_info("auth request: GET from %s, Authorization=%s",
			 remote_addr,
			 (auth_header && auth_header[0]) ? "present" : "empty");

		log_info("auth step1: parsing Basic auth...");
		if (parse_basic_auth(auth_header, username, sizeof(username),
				     password, sizeof(password)) == 0) {
			log_info("auth step1 OK: Basic auth parsed, user=%s",
				 username);
		} else {
			log_info("auth step1: no Basic auth credentials");
		}
	} else {
		/* POST: 从 JSON body 解析 */
		log_info("auth request: POST from %s", remote_addr);

		log_info("auth step1: parsing POST body...");
		if (parse_post_body(req, username, sizeof(username),
				    password, sizeof(password)) == 0) {
			log_info("auth step1 OK: POST body parsed, user=%s",
				 username);
		} else {
			log_warn("auth step1 FAIL: POST body parse failed "
				 "or missing fields");
			send_json_reply(req, 400, "Bad Request",
					"{\"error\":\"missing username or password\"}");
			return;
		}
	}

	/* 步骤 2: 检查 session 是否就绪 */
	log_info("auth step2: checking session...");
	if (!session_valid(ctx->sess)) {
		log_warn("auth step2 FAIL: session not ready (join pending), "
			 "returning 503");
		send_json_reply(req, 503, "Session Not Ready",
				"{\"error\":\"session not ready\"}");
		return;
	}
	log_info("auth step2 OK: session valid (id=%.16s...)",
		 ctx->sess->session_id);

	/* 步骤 3: 补齐 device_id 等字段，发往远程认证服务器 */
	log_info("auth step3: calling remote authenticate "
		 "(cfg=%s://%s:%d%s, user=%s)",
		 protocol_str(ctx->cfg->auth_remote_proto),
		 ctx->cfg->auth_remote_host,
		 ctx->cfg->auth_remote_port,
		 ctx->cfg->auth_remote_path,
		 username[0] ? username : "(none)");
	rc = auth_remote_authenticate(ctx->cfg, ctx->dev, ctx->sess,
				     username, password,
				     (method == EVHTTP_REQ_GET) ? auth_header : NULL,
				     &result);
	if (rc < 0) {
		log_err("auth step3 FAIL: remote authenticate rc=%d, "
			"returning 503", rc);
		send_json_reply(req, 503, "Service Unavailable",
				"{\"error\":\"remote auth unavailable\"}");
		return;
	}
	log_info("auth step3 OK: remote returned (approved=%d, "
		 "user=%s, reason=%s)",
		 result.approved,
		 result.username[0] ? result.username : "(none)",
		 result.reason[0] ? result.reason : "n/a");

	/* 步骤 4: 检查远程认证是否通过 */
	if (!result.approved) {
		log_warn("auth step4 FAIL: denied by remote, reason=%s, "
			 "returning 401",
			 result.reason[0] ? result.reason : "unknown");
		{
			char body[256];
			snprintf(body, sizeof(body),
				 "{\"error\":\"%s\"}",
				 result.reason[0] ? result.reason : "denied");
			send_json_reply(req, 401, "Unauthorized", body);
		}
		return;
	}
	log_info("auth step4 OK: approved by remote, user=%s",
		 result.username[0] ? result.username : "(unknown)");

	/* 步骤 5: 读取 /etc/config/localpasswd 解密得到 LuCI 密码
	 * （文件不存在或解密失败时回退为空密码） */
	log_info("auth step5: getting local password...");
	if (auth_local_get_password(luci_password,
				    sizeof(luci_password)) < 0) {
		log_err("auth step5 FAIL: get local password failed, "
			"returning 503");
		send_json_reply(req, 503, "Service Unavailable",
				"{\"error\":\"local password unavailable\"}");
		return;
	}
	/* 解密失败时 auth_local_get_password 回退为空密码；
	 * 若配置了默认密码，用它代替，打破"解密失败→空密码→
	 * step6 503→step7 不执行→永不修复"的死循环。 */
	if (luci_password[0] == 0 && ctx->cfg->auth_default_password[0]) {
		log_warn("auth step5: local password empty (decrypt failed?), "
			 "using config default_password");
		snprintf(luci_password, sizeof(luci_password), "%s",
			 ctx->cfg->auth_default_password);
	}
	log_info("auth step5 OK: local password obtained (len=%zu)",
		 strlen(luci_password));

	/* 步骤 6: 用 root + 该密码登录 UBUS rpcd（session.login） */
	log_info("auth step6: logging in to UBUS (session.login)...");
	rc = auth_local_ubus_login(luci_password, &luci_token);
	if (rc < 0) {
		log_err("auth step6 FAIL: ubus session login failed, returning 503");
		send_json_reply(req, 503, "Service Unavailable",
				"{\"error\":\"ubus session login failed\"}");
		return;
	}
	log_info("auth step6 OK: ubus sid=%.16s..., valid=%d, ttl=%ds",
		 luci_token.token, luci_token.valid, luci_token.expires);

	/* 步骤 7: 登录成功后设置本机密码。
	 *   - 开关开启：生成新随机密码并轮换（原逻辑）
	 *   - 开关关闭：用配置默认用户名/密码设置（写 localpasswd 并 passwd）
	 * 失败不阻塞认证（当前 token 已有效），仅记录日志。 */
	if (ctx->cfg->auth_modify_local_password) {
		log_info("auth step7: rotating local password...");
		if (auth_local_rotate_password(NULL, 0) < 0) {
			log_warn("auth step7 FAIL: password rotation failed "
				 "(non-fatal, current token still valid)");
		} else {
			log_info("auth step7 OK: password rotated");
		}
	} else {
		log_info("auth step7 (switch off): setting default credentials for %s",
			 ctx->cfg->auth_default_username);
		if (auth_local_set_password(ctx->cfg->auth_default_username,
					    ctx->cfg->auth_default_password) < 0) {
			log_warn("auth step7 FAIL: set default password failed "
				 "(non-fatal, current token still valid)");
		} else {
			log_info("auth step7 OK: default credentials set for %s",
				 ctx->cfg->auth_default_username);
		}
	}

	/* 步骤 8: 返回成功 + 双 token + 用户信息给 nginx */
	log_info("auth step8: returning 200 to nginx "
		 "(auth_token=%.16s%s, luci_token=%.16s..., "
		 "forwarded_user=%s, forwarded_email=%s)",
		 result.token[0] ? result.token : "(none)",
		 result.token[0] ? "..." : "",
		 luci_token.token,
		 result.username[0] ? result.username : "(empty)",
		 result.email[0] ? result.email : "(empty)");

	{
		char body[1024];
		snprintf(body, sizeof(body),
			 "{\"approved\":true,"
			 "\"auth_token\":\"%s\","
			 "\"luci_token\":\"%s\","
			 "\"username\":\"%s\"}",
			 result.token, luci_token.token,
			 result.username);

		struct evbuffer *buf = evbuffer_new();
		evbuffer_add_printf(buf, "%s", body);

		evhttp_add_header(evhttp_request_get_output_headers(req),
				  "Content-Type", "application/json");
		/* 认证服务器的 token（远程认证下发，nginx 捕获，不转发给 LuCI） */
		evhttp_add_header(evhttp_request_get_output_headers(req),
				  "X-Auth-Token", result.token);
		/* LuCI 的 sysauth session ID（nginx 捕获后注入为 Cookie: sysauth） */
		evhttp_add_header(evhttp_request_get_output_headers(req),
				  "X-LuCI-Token", luci_token.token);
		/* 认证通过的用户名（nginx 转发给 LuCI） */
		if (result.username[0])
			evhttp_add_header(
				evhttp_request_get_output_headers(req),
				"X-Forwarded-User", result.username);
		/* 用户邮箱（可选，nginx 转发给 LuCI） */
		if (result.email[0])
			evhttp_add_header(
				evhttp_request_get_output_headers(req),
				"X-Forwarded-Email", result.email);

		evhttp_send_reply(req, 200, "OK", buf);
		evbuffer_free(buf);
	}
	log_info("auth request completed: 200 OK sent to nginx");
}

void auth_server_init_ctx(auth_server_ctx_t *ctx,
			  struct event_base *base,
			  const xfrpc_config_t *cfg,
			  const device_info_t *dev,
			  const session_info_t *sess)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->base = base;
	ctx->cfg = cfg;
	ctx->dev = dev;
	ctx->sess = sess;
}

int auth_server_start(auth_server_ctx_t *ctx)
{
	if (!ctx->cfg->auth_enabled)
		return 0;	/* 未启用，直接返回（不报错） */

	/* 创建 evhttp 并绑定端口。
	 * 不预初始化本地密码——新逻辑中密码按需获取并轮换。 */
	ctx->http = evhttp_new(ctx->base);
	if (!ctx->http) {
		log_err("auth: evhttp_new failed");
		return -1;
	}

	if (evhttp_bind_socket(ctx->http, "127.0.0.1",
			       (u_short)ctx->cfg->auth_listen_port) < 0) {
		log_err("auth: bind 127.0.0.1:%d failed",
			ctx->cfg->auth_listen_port);
		evhttp_free(ctx->http);
		ctx->http = NULL;
		return -1;
	}

	evhttp_set_cb(ctx->http, "/auth", handle_auth_request, ctx);
	evhttp_set_cb(ctx->http, "/api/password", handle_get_password, ctx);
	ctx->server_ready = 1;

	log_info("auth: server listening on 127.0.0.1:%d",
		 ctx->cfg->auth_listen_port);
	return 0;
}

void auth_server_stop(auth_server_ctx_t *ctx)
{
	if (ctx->http) {
		evhttp_free(ctx->http);
		ctx->http = NULL;
		ctx->server_ready = 0;
		log_info("auth: server stopped");
	}
}
