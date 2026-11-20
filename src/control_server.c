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
 *
 * webauthd-control/v1 服务端。
 *
 * 设计要点：
 *   - xfrpc_loader 是控制面，webauthd 是执行面；
 *   - webauthd 主动连接并拉取期望状态；
 *   - 期望状态由 session 实时计算，同一事件循环内无并发；
 *   - generation 只在内容变化时递增，避免执行面重复应用；
 *   - ACK 中的 restart_required 由本模块触发一次节流后的受控重启。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE	/* struct ucred / SO_PEERCRED */
#endif

#include "control_server.h"
#include "instance.h"
#include "log.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <json-c/json.h>

#define CONTROL_SCHEMA		"webauthd-control/v1"
#define CONTROL_LEASE_SEC	20
#define CONTROL_REQ_MAX		4096
#define CONTROL_RESP_MAX	16384
#define CONTROL_RESTART_MIN	30	/* 秒，冷重启节流 */

struct control_conn {
	control_server_ctx_t	*srv;
	struct bufferevent	*bev;
	char			req[CONTROL_REQ_MAX];
	size_t			req_len;
	int			awaiting_ack;
};

static void conn_free(struct control_conn *c)
{
	if (!c)
		return;
	if (c->bev)
		bufferevent_free(c->bev);
	free(c);
}

static int radius_complete(const session_info_t *s)
{
	return s &&
	       s->radius_auth_server[0] && s->radius_acct_server[0] &&
	       s->radius_nas_ip[0] &&
	       s->radius_auth_secret[0] && s->radius_acct_secret[0] &&
	       s->radius_auth_port > 0 && s->radius_acct_port > 0;
}

/*
 * 构造不含 generation 的期望状态体。
 * 返回 json_object，调用方负责 json_object_put。
 */
static struct json_object *build_state_body(inst_t *inst)
{
	struct json_object *root;
	struct json_object *portal;
	struct json_object *auth;
	struct json_object *radius;
	const char *profile;
	const char *reason;
	const char *host;
	int has_session;
	int has_radius;

	root = json_object_new_object();
	if (!root)
		return NULL;

	has_session = session_valid(&inst->session);
	has_radius = has_session && radius_complete(&inst->session);

	json_object_object_add(root, "schema",
			       json_object_new_string(CONTROL_SCHEMA));
	json_object_object_add(root, "managed", json_object_new_boolean(1));
	json_object_object_add(root, "lease_sec",
			       json_object_new_int(CONTROL_LEASE_SEC));

	if (has_session) {
		profile = "cloud";
		reason = "session_running";
	} else {
		profile = "fallback";
		switch (inst->current) {
		case ST_JOINING:
			reason = "unjoined";
			break;
		case ST_REJOIN:
			reason = "rejoin";
			break;
	 default:
			reason = "no_session";
			break;
		}
	}

	json_object_object_add(root, "profile",
			       json_object_new_string(profile));
	json_object_object_add(root, "reason",
			       json_object_new_string(reason));

	if (strcmp(profile, "cloud") != 0)
		return root;

	host = inst->cfg.server_name[0] ? inst->cfg.server_name :
	       inst->cfg.server_ip;
	if (!host || !host[0]) {
		/* 没有可用云地址时不下发 Portal，等下一次 join 或配置生效 */
		json_object_object_add(root, "profile",
				       json_object_new_string("fallback"));
		json_object_object_add(root, "reason",
				       json_object_new_string("no_portal_host"));
		return root;
	}

	portal = json_object_new_object();
	json_object_object_add(portal, "portal_type",
			       json_object_new_int(3));
	{
		char url[1100];
		snprintf(url, sizeof(url), "http://%s:9091", host);
		json_object_object_add(portal, "portal_url",
				       json_object_new_string(url));
	}
	if (strlen(host) < 16) {
		json_object_object_add(portal, "portal_server",
				       json_object_new_string(host));
	}
	json_object_object_add(portal, "portal_port",
			       json_object_new_int(9091));
	json_object_object_add(root, "portal", portal);

	/* 云端没下发 RADIUS 时只切 Portal，认证源保持 webauthd 本地基线 */
	if (!has_radius)
		return root;

	auth = json_object_new_object();
	json_object_object_add(auth, "auth_source",
			       json_object_new_string("radius"));
	json_object_object_add(auth, "local_radius_client",
			       json_object_new_int(0));

	radius = json_object_new_object();
	json_object_object_add(radius, "auth_server",
			       json_object_new_string(
				       inst->session.radius_auth_server));
	json_object_object_add(radius, "auth_port",
			       json_object_new_int(
				       inst->session.radius_auth_port));
	json_object_object_add(radius, "auth_secret",
			       json_object_new_string(
				       inst->session.radius_auth_secret));
	json_object_object_add(radius, "acct_server",
			       json_object_new_string(
				       inst->session.radius_acct_server));
	json_object_object_add(radius, "acct_port",
			       json_object_new_int(
				       inst->session.radius_acct_port));
	json_object_object_add(radius, "acct_secret",
			       json_object_new_string(
				       inst->session.radius_acct_secret));
	json_object_object_add(radius, "nas_ip",
			       json_object_new_string(
				       inst->session.radius_nas_ip));
	if (inst->session.tenant_org_id[0]) {
		json_object_object_add(radius, "tenant_org_id",
				       json_object_new_string(
					       inst->session.tenant_org_id));
	}
	json_object_object_add(auth, "radius", radius);
	json_object_object_add(root, "auth", auth);

	return root;
}

/*
 * 生成当前状态 JSON 字符串（单行，以 \n 结尾由调用方追加）。
 */
static int build_state(control_server_ctx_t *srv, char **out)
{
	inst_t *inst = srv->inst;
	struct json_object *body;
	char *body_str;
	const char *full;
	int changed;

	body = build_state_body(inst);
	if (!body)
		return -1;

	body_str = strdup(json_object_to_json_string(body));
	if (!body_str) {
		json_object_put(body);
		return -1;
	}

	changed = (!srv->last_body || strcmp(srv->last_body, body_str) != 0);
	if (changed) {
		if (srv->generation == 0)
			srv->generation = (uint64_t)time(NULL);
		else
			srv->generation++;
		free(srv->last_body);
		srv->last_body = body_str;
	} else {
		free(body_str);
	}

	json_object_object_add(body, "generation",
			       json_object_new_int64((int64_t)srv->generation));
	full = json_object_to_json_string(body);
	*out = strdup(full ? full : "{}");
	json_object_put(body);

	return *out ? 0 : -1;
}

static void restart_webauthd(control_server_ctx_t *srv)
{
	pid_t pid;
	time_t now = time(NULL);

	if (now - srv->last_restart_time < CONTROL_RESTART_MIN) {
		log_debug("webauthd restart already requested recently, skip");
		return;
	}
	srv->last_restart_time = now;

	log_info("webauthd requested cold restart, invoking init script");
	pid = fork();
	if (pid == 0) {
		setsid();
		execl("/etc/init.d/webauthd", "webauthd", "restart",
		      (char *)NULL);
		_exit(127);
	} else if (pid < 0) {
		log_err("fork for webauthd restart failed: %s", strerror(errno));
	}
}

static void send_error(struct bufferevent *bev, int code, const char *msg)
{
	struct json_object *root = json_object_new_object();
	char buf[256];

	if (!root)
		return;
	json_object_object_add(root, "schema",
			       json_object_new_string(CONTROL_SCHEMA));
	json_object_object_add(root, "error_code",
			       json_object_new_int(code));
	json_object_object_add(root, "error_msg",
			       json_object_new_string(msg ? msg : ""));
	snprintf(buf, sizeof(buf), "%s\n",
		 json_object_to_json_string(root));
	bufferevent_write(bev, buf, strlen(buf));
	bufferevent_enable(bev, EV_WRITE);	/* 待发完错误响应后由 on_write 关闭 */
	json_object_put(root);
}

static int handle_get_state(struct control_conn *c)
{
	char *state = NULL;
	char line[CONTROL_RESP_MAX + 2];

	if (build_state(c->srv, &state) < 0) {
		send_error(c->bev, -1010, "build state failed");
		return -1;
	}
	if (strlen(state) > CONTROL_RESP_MAX) {
		free(state);
		send_error(c->bev, -1010, "state too large");
		return -1;
	}
	snprintf(line, sizeof(line), "%s\n", state);
	bufferevent_write(c->bev, line, strlen(line));
	bufferevent_enable(c->bev, EV_WRITE);
	free(state);
	c->awaiting_ack = 1;
	log_debug("control: sent state generation=%llu",
		  (unsigned long long)c->srv->generation);
	return 0;
}

static int handle_ack(struct control_conn *c, struct json_object *root)
{
	struct json_object *jgen;
	struct json_object *jstatus;
	struct json_object *jerr;
	struct json_object *jmsg;
	uint64_t gen = 0;
	const char *status = "";
	int err = 0;
	const char *msg = "";

	if (json_object_object_get_ex(root, "generation", &jgen))
		gen = (uint64_t)json_object_get_int64(jgen);
	if (json_object_object_get_ex(root, "status", &jstatus))
		status = json_object_get_string(jstatus);
	if (json_object_object_get_ex(root, "error_code", &jerr))
		err = json_object_get_int(jerr);
	if (json_object_object_get_ex(root, "error_msg", &jmsg))
		msg = json_object_get_string(jmsg);

	c->srv->last_ack_generation = gen;
	c->srv->last_ack_error = err;
	c->srv->last_ack_time = time(NULL);
	snprintf(c->srv->last_ack_status,
		 sizeof(c->srv->last_ack_status), "%s", status ? status : "");

	log_info("control: webauthd ack gen=%llu status=%s err=%d msg=%s",
		 (unsigned long long)gen, status ? status : "", err,
		 msg ? msg : "");

	if (strcmp(status, "restart_required") == 0)
		restart_webauthd(c->srv);

	return 0;
}

static int handle_request(struct control_conn *c, const char *line)
{
	struct json_object *root;
	struct json_object *jop;
	const char *op;
	int ret;

	root = json_tokener_parse(line);
	if (!root || json_object_get_type(root) != json_type_object) {
		log_warn("control: invalid JSON request");
		if (root)
			json_object_put(root);
		send_error(c->bev, -1003, "invalid JSON");
		return -1;
	}

	if (!json_object_object_get_ex(root, "op", &jop)) {
		json_object_put(root);
		send_error(c->bev, -1000, "missing op");
		return -1;
	}
	op = json_object_get_string(jop);

	if (strcmp(op, "get_state") == 0)
		ret = handle_get_state(c);
	else if (strcmp(op, "ack") == 0)
		ret = handle_ack(c, root);
	else {
		send_error(c->bev, -1000, "unknown op");
		ret = -1;
	}

	json_object_put(root);
	return ret;
}

static void on_write(struct bufferevent *bev, void *arg)
{
	struct control_conn *c = arg;

	/* EV_WRITE 为电平触发，数据发空后立即禁用，避免空转 */
	bufferevent_disable(bev, EV_WRITE);
	if (c->awaiting_ack)
		return;
	if (evbuffer_get_length(bufferevent_get_output(bev)) == 0)
		conn_free(c);
}

static void on_event(struct bufferevent *bev, short events, void *arg)
{
	struct control_conn *c = arg;

	(void)bev;
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
		if (events & BEV_EVENT_ERROR)
			log_warn("control: connection error: %s",
				 evutil_socket_error_to_string(
					 EVUTIL_SOCKET_ERROR()));
		else if (events & BEV_EVENT_TIMEOUT)
			log_debug("control: connection timeout");
		conn_free(c);
	}
}

static void on_read(struct bufferevent *bev, void *arg)
{
	struct control_conn *c = arg;
	char *nl;
	size_t n;

	if (c->awaiting_ack) {
		/* 第二段：ACK */
		n = bufferevent_read(bev, c->req, sizeof(c->req) - 1);
		if (n == 0)
			return;
		c->req[n] = '\0';
		nl = strchr(c->req, '\n');
		if (nl)
			*nl = '\0';
		if (c->req[0])
			handle_request(c, c->req);
		/* ACK 处理完成；输出（若有错误）排空后由 on_write 释放 */
		c->awaiting_ack = 0;
		if (evbuffer_get_length(bufferevent_get_output(bev)) == 0)
			conn_free(c);
		return;
	}

	n = bufferevent_read(bev, c->req + c->req_len,
			     sizeof(c->req) - 1 - c->req_len);
	if (n == 0)
		return;
	c->req_len += n;
	c->req[c->req_len] = '\0';

	if (c->req_len >= sizeof(c->req) - 1) {
		log_warn("control: request too large, closing");
		conn_free(c);
		return;
	}

	nl = strchr(c->req, '\n');
	if (!nl)
		return;	/* 等待完整的一行 */

	*nl = '\0';
	c->req_len = 0;
	if (c->req[0])
		handle_request(c, c->req);
}

static void on_accept(struct evconnlistener *listener, evutil_socket_t fd,
		      struct sockaddr *addr, int addrlen, void *arg)
{
	control_server_ctx_t *srv = arg;
	struct control_conn *c;
	struct timeval tv = { 10, 0 };
#if defined(SO_PEERCRED) && defined(__linux__)
	struct ucred cred;
	socklen_t cred_len = sizeof(cred);
#endif

	(void)listener;
	(void)addr;
	(void)addrlen;

#if defined(SO_PEERCRED) && defined(__linux__)
	/* 控制通道只允许 root 连接；socket 文件权限之外再校验对端身份。 */
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0 ||
	    cred.uid != 0) {
		log_warn("control: reject non-root peer");
		close(fd);
		return;
	}
#endif

	c = calloc(1, sizeof(*c));
	if (!c) {
		close(fd);
		return;
	}
	c->srv = srv;
	c->bev = bufferevent_socket_new(evconnlistener_get_base(listener), fd,
					BEV_OPT_CLOSE_ON_FREE);
	if (!c->bev) {
		log_err("control: bufferevent_socket_new failed");
		free(c);
		close(fd);
		return;
	}
	bufferevent_set_timeouts(c->bev, &tv, &tv);
	bufferevent_setcb(c->bev, on_read, on_write, on_event, c);
	/* 关键：accept 后只开 EV_READ。EV_WRITE 是电平触发，
	 * 连接刚建立即触发 on_write 会把新连接误判为"数据已发空"
	 * 直接 conn_free，导致客户端 connect 成功后被立即 RST。 */
	bufferevent_enable(c->bev, EV_READ);
}

int control_server_start(control_server_ctx_t *srv, struct event_base *base,
			 struct inst_t *inst)
{
	struct sockaddr_un sun;
	struct stat st;
	int fd;

	if (!srv || !base || !inst)
		return -1;

	memset(srv, 0, sizeof(*srv));
	srv->inst = inst;

	if (mkdir(CONTROL_SOCKET_DIR, 0700) < 0 && errno != EEXIST) {
		log_warn("control: mkdir %s failed: %s", CONTROL_SOCKET_DIR,
			 strerror(errno));
		return -1;
	}
	chmod(CONTROL_SOCKET_DIR, 0700);

	if (lstat(CONTROL_SOCKET_PATH, &st) == 0) {
		if (S_ISDIR(st.st_mode)) {
			log_warn("control: %s is a directory, refusing to remove",
				 CONTROL_SOCKET_PATH);
			return -1;
		}
		unlink(CONTROL_SOCKET_PATH);
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		log_warn("control: socket failed: %s", strerror(errno));
		return -1;
	}
	evutil_make_socket_nonblocking(fd);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", CONTROL_SOCKET_PATH);

	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		log_warn("control: bind %s failed: %s", CONTROL_SOCKET_PATH,
			 strerror(errno));
		close(fd);
		return -1;
	}
	chmod(CONTROL_SOCKET_PATH, 0600);

	srv->listener = evconnlistener_new(base, on_accept, srv,
					   LEV_OPT_CLOSE_ON_FREE |
					   LEV_OPT_REUSEABLE, 16, fd);
	if (!srv->listener) {
		log_warn("control: evconnlistener_new failed");
		close(fd);
		unlink(CONTROL_SOCKET_PATH);
		return -1;
	}

	log_info("control: listening on %s", CONTROL_SOCKET_PATH);
	return 0;
}

void control_server_stop(control_server_ctx_t *srv)
{
	if (!srv)
		return;
	if (srv->listener) {
		evconnlistener_free(srv->listener);
		srv->listener = NULL;
	}
	unlink(CONTROL_SOCKET_PATH);
	free(srv->last_body);
	srv->last_body = NULL;
}
