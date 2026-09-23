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
#include "instance.h"
#include "http_client.h"
#include "xfrpc_manager.h"
#include "system_status.h"
#include "protocol.h"
#include "auth_local.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>

#define CA_KEY_FILE "/etc/config/ca.key"

/* 检查并更新 CA 公钥文件 */
static void update_ca_key(const char *ca_pub_key)
{
	FILE *f;
	char existing[1024];
	size_t n;

	if (!ca_pub_key || !ca_pub_key[0])
		return;

	/* 读取现有文件内容 */
	f = fopen(CA_KEY_FILE, "r");
	if (f) {
		n = fread(existing, 1, sizeof(existing) - 1, f);
		fclose(f);
		existing[n] = 0;
		/* 去除尾部空白便于比较 */
		while (n > 0 && (existing[n - 1] == '\n' || existing[n - 1] == '\r' ||
				 existing[n - 1] == ' ' || existing[n - 1] == '\t'))
			existing[--n] = 0;
		if (strcmp(existing, ca_pub_key) == 0) {
			log_debug("CA key unchanged, skip save");
			return;
		}
		log_info("CA key changed, updating %s", CA_KEY_FILE);
	} else {
		log_info("CA key file not exist, creating %s", CA_KEY_FILE);
	}

	/* 写入新内容 */
	f = fopen(CA_KEY_FILE, "w");
	if (!f) {
		log_err("cannot write %s: %s", CA_KEY_FILE, strerror(errno));
		return;
	}
	fprintf(f, "%s\n", ca_pub_key);
	fclose(f);
}

/* ---- 前向声明 ---- */

static void status_timer_cb(evutil_socket_t fd, short what, void *arg);
static void retry_timer_cb(evutil_socket_t fd, short what, void *arg);
static void xfrpc_restart_cb(evutil_socket_t fd, short what, void *arg);

static void init_enter(inst_t *inst);
static void init_event(inst_t *inst, sm_event_t ev, void *data);

static void joining_enter(inst_t *inst);
static void joining_event(inst_t *inst, sm_event_t ev, void *data);

static void running_enter(inst_t *inst);
static void running_exit(inst_t *inst);
static void running_event(inst_t *inst, sm_event_t ev, void *data);

static void rejoin_enter(inst_t *inst);
static void rejoin_exit(inst_t *inst);
static void rejoin_event(inst_t *inst, sm_event_t ev, void *data);

static void term_enter(inst_t *inst);

/* ---- 回调表 ---- */

static const state_callbacks_t state_cbs[ST_MAX] = {
	[ST_INIT]	= { init_enter,    NULL,         init_event    },
	[ST_JOINING]	= { joining_enter, NULL,         joining_event },
	[ST_RUNNING]	= { running_enter, running_exit, running_event },
	[ST_REJOIN]	= { rejoin_enter,  rejoin_exit,  rejoin_event  },
	[ST_TERM]	= { term_enter,    NULL,         NULL          },
};

/* ---- 工具函数 ---- */

const char *state_name(state_t s)
{
	switch (s) {
	case ST_INIT:	return "INIT";
	case ST_JOINING:	return "JOINING";
	case ST_RUNNING:	return "RUNNING";
	case ST_REJOIN:	return "REJOIN";
	case ST_TERM:	return "TERM";
	default:	return "UNKNOWN";
	}
}

/* ---- 核心调度 ---- */

void sm_init(inst_t *inst)
{
	int i;

	inst->current = ST_INIT;

	for (i = 0; i < ST_MAX; i++)
		inst->cbs[i] = &state_cbs[i];

	/* 创建定时器（尚未加入事件循环） */
	inst->status_timer = event_new(inst->base, -1, EV_PERSIST,
				       status_timer_cb, inst);
	inst->retry_timer = event_new(inst->base, -1, 0,
				      retry_timer_cb, inst);
	inst->xfrpc_restart_timer = event_new(inst->base, -1, 0,
					      xfrpc_restart_cb, inst);

	/* 初始化 auth server 上下文（不启动 evhttp） */
	auth_server_init_ctx(&inst->auth, inst->base, &inst->cfg, &inst->dev,
			     &inst->session);
}

void sm_transition(inst_t *inst, state_t next)
{
	state_t prev = inst->current;

	if (inst->cbs[prev] && inst->cbs[prev]->exit)
		inst->cbs[prev]->exit(inst);

	log_debug("state: %s -> %s", state_name(prev), state_name(next));
	inst->current = next;

	if (inst->cbs[next] && inst->cbs[next]->enter)
		inst->cbs[next]->enter(inst);
}

void sm_dispatch(inst_t *inst, sm_event_t ev, void *data)
{
	if (inst->cbs[inst->current] && inst->cbs[inst->current]->event)
		inst->cbs[inst->current]->event(inst, ev, data);
}

/* ---- 辅助函数 ---- */

/*
 * 计算 join 失败后的退避等待时间(秒)。
 * 指数退避：每次连续失败间隔翻倍，封顶在 max_retry_interval；
 * 叠加最多 +25% 的随机抖动，避免大量设备同步重试，抖动后同样封顶，
 * 保证重试间隔不会越来越大。
 */
static int rejoin_backoff_seconds(const xfrpc_config_t *cfg, int attempt)
{
	int delay = cfg->retry_interval;
	int cap = cfg->max_retry_interval;
	int i;

	/* 上限不低于基础间隔，避免配置错误时退避比 retry_interval 还小 */
	if (cap < delay)
		cap = delay;

	for (i = 1; i < attempt; i++) {
		if (delay >= cap)
			break;
		if (delay > cap / 2) {
			delay = cap;
			break;
		}
		delay *= 2;
	}

	if (delay > cfg->retry_interval)
		delay += rand() % (delay / 4 + 1);

	if (delay > cap)
		delay = cap;

	return delay;
}

static void on_join_success(inst_t *inst, const join_response_t *resp)
{
	session_set(&inst->session, resp);
	inst->join_retry_count = 0;

	/* 服务器下发的 CA 公钥，检查并保存到本地 */
	update_ca_key(resp->ca_pub_key);

	log_info("join ok, session=%s, xfrpc=%s:%d",
		 inst->session.session_id,
		 inst->session.xfrpc_server_addr,
		 inst->session.xfrpc_server_port);
}

static void xfrpc_handle_exit(inst_t *inst, int status)
{
	time_t now;

	log_warn("xfrpc exited, status=%d", status);

	/* xfrpc_pid 已由 SIGCHLD 回调置为 -1 */
	now = time(NULL);
	if (now - inst->xfrpc_first_crash > 30) {
		/* 重置崩溃计数窗口 */
		inst->xfrpc_first_crash = now;
		inst->xfrpc_restart_count = 0;
	}
	inst->xfrpc_restart_count++;

	if (inst->xfrpc_restart_count > 3) {
		log_err("xfrpc crashed %d times in 30s, giving up",
			inst->xfrpc_restart_count);
		return;
	}

	log_info("xfrpc will restart in 5s (crash #%d)",
		 inst->xfrpc_restart_count);

	struct timeval tv = { 5, 0 };
	event_add(inst->xfrpc_restart_timer, &tv);
}

/* ---- ST_INIT ---- */

static void init_enter(inst_t *inst)
{
	if (config_load_json(&inst->cfg, CONFIG_PATH) < 0) {
		sm_dispatch(inst, EV_CFG_FAILED, NULL);
		return;
	}
	if (device_info_collect(&inst->dev, inst->cfg.local_if) < 0) {
		log_err("device info collection failed");
		sm_dispatch(inst, EV_CFG_FAILED, NULL);
		return;
	}

	/* "修改本机密码"开关关闭（默认）时，开机即用配置的默认用户名/密码
	 * 设置 root/LuCI 密码（写 localpasswd 并 passwd），保证 root 密码非空，
	 * 避免空密码直连 /cgi-bin/luci/rpc/auth 直接拿到登录态（测试期锁死用户）。
	 * 失败仅记录日志，不阻塞主流程。 */
	if (!inst->cfg.auth_modify_local_password) {
		if (auth_local_set_password(inst->cfg.auth_default_username,
					    inst->cfg.auth_default_password) < 0) {
			log_warn("init: set default local password failed "
				 "(default_password may be empty)");
		}
	}

	/* 认证服务器：配置+设备信息就绪后立即启动（只要 enabled）。
	 * 不等待 join，端口先监听起来，未 join 时请求返回 503。
	 * 失败仅记录日志，不阻塞主流程。 */
	if (inst->cfg.auth_enabled)
		auth_server_start(&inst->auth);

	sm_dispatch(inst, EV_CFG_LOADED, NULL);
}

static void init_event(inst_t *inst, sm_event_t ev, void *data)
{
	(void)data;

	switch (ev) {
	case EV_CFG_LOADED:
		sm_transition(inst, ST_JOINING);
		break;
	case EV_CFG_FAILED:
		log_err("configuration failed, exiting");
		sm_transition(inst, ST_TERM);
		break;
	default:
		break;
	}
}

/* ---- ST_JOINING ---- */

static void joining_enter(inst_t *inst)
{
	join_response_t resp;
	int ret;

	memset(&resp, 0, sizeof(resp));

	ret = http_join(&inst->cfg, &inst->dev, &resp, inst->cfg.join_timeout);

	switch (ret) {
	case 0:
		sm_dispatch(inst, EV_JOIN_OK, &resp);
		break;
	case -ETIMEDOUT:
		sm_dispatch(inst, EV_JOIN_TIMEOUT, NULL);
		break;
	case -EACCES:
		sm_dispatch(inst, EV_JOIN_REJECTED, NULL);
		break;
	default:
		sm_dispatch(inst, EV_JOIN_FAIL, NULL);
		break;
	}
}

static void joining_event(inst_t *inst, sm_event_t ev, void *data)
{
	switch (ev) {
	case EV_JOIN_OK:
		on_join_success(inst, (const join_response_t *)data);
		sm_transition(inst, ST_RUNNING);
		break;
	case EV_JOIN_FAIL:
		log_warn("join failed, will retry");
		sm_transition(inst, ST_REJOIN);
		break;
	case EV_JOIN_REJECTED:
		/* 服务端拒绝（-1001/-1002）不终止：退避后继续尝试，
		 * 直到加入成功或收到 SIGTERM。 */
		log_warn("join rejected by server (-1001/-1002), will retry with backoff");
		sm_transition(inst, ST_REJOIN);
		break;
	case EV_JOIN_TIMEOUT:
		log_warn("join timeout after %ds", inst->cfg.join_timeout);
		sm_transition(inst, ST_REJOIN);
		break;
	case EV_SIGTERM:
		sm_transition(inst, ST_TERM);
		break;
	default:
		break;
	}
}

/* ---- ST_RUNNING ---- */

static void running_enter(inst_t *inst)
{
	/* 生成 ini 并启动 xfrpc */
	if (xfrpc_generate_ini(&inst->session, &inst->dev) < 0) {
		log_err("generate xfrpc.ini failed, continuing without xfrpc");
	} else {
		pid_t pid = xfrpc_spawn();
		if (pid > 0) {
			inst->xfrpc_pid = pid;
			log_info("xfrpc started, pid=%d", pid);
		} else {
			log_err("xfrpc spawn failed");
		}
	}

	/* 启动周期状态定时器 */
	struct timeval tv = { inst->cfg.status_interval, 0 };
	event_add(inst->status_timer, &tv);

	log_info("session running, status interval=%ds",
		 inst->cfg.status_interval);
}

static void running_exit(inst_t *inst)
{
	pid_t pid;

	event_del(inst->status_timer);
	event_del(inst->xfrpc_restart_timer);	/* 取消待处理的重启 */

	/* 停止 xfrpc：先标记 pid=-1，让 SIGCHLD 回调忽略此退出 */
	pid = inst->xfrpc_pid;
	inst->xfrpc_pid = -1;
	if (pid > 0)
		xfrpc_stop(pid);

	xfrpc_delete_ini();
	session_invalidate(&inst->session);
	inst->xfrpc_restart_count = 0;
}

static void running_event(inst_t *inst, sm_event_t ev, void *data)
{
	switch (ev) {
	case EV_STATUS_OK:
		log_debug("status ok");
		break;
	case EV_STATUS_FAIL:
		log_warn("status failed, session lost");
		sm_transition(inst, ST_REJOIN);
		break;
	case EV_STATUS_TIMEOUT:
		log_warn("status timeout, session lost");
		sm_transition(inst, ST_REJOIN);
		break;
	case EV_XFRPC_EXITED:
		xfrpc_handle_exit(inst, (int)(intptr_t)data);
		break;
	case EV_SIGTERM:
		sm_transition(inst, ST_TERM);
		break;
	default:
		break;
	}
}

/* ---- ST_REJOIN ---- */

static void rejoin_enter(inst_t *inst)
{
	int delay;

	inst->join_retry_count++;

	if (inst->cfg.max_join_retries > 0 &&
	    inst->join_retry_count > inst->cfg.max_join_retries) {
		log_err("max join retries (%d) exceeded, giving up",
			inst->cfg.max_join_retries);
		sm_transition(inst, ST_TERM);
		return;
	}

	/* 指数退避：连续失败间隔翻倍，最高 max_retry_interval */
	delay = rejoin_backoff_seconds(&inst->cfg, inst->join_retry_count);
	log_info("waiting %ds before rejoin (attempt %d, backoff)",
		 delay, inst->join_retry_count);

	struct timeval tv = { delay, 0 };
	event_add(inst->retry_timer, &tv);
}

static void rejoin_exit(inst_t *inst)
{
	event_del(inst->retry_timer);
}

static void rejoin_event(inst_t *inst, sm_event_t ev, void *data)
{
	(void)data;

	switch (ev) {
	case EV_RETRY_EXPIRED:
		sm_transition(inst, ST_JOINING);
		break;
	case EV_SIGTERM:
		sm_transition(inst, ST_TERM);
		break;
	default:
		break;
	}
}

/* ---- ST_TERM ---- */

static void term_enter(inst_t *inst)
{
	pid_t pid;

	/* 停止认证服务器 */
	if (inst->auth.http)
		auth_server_stop(&inst->auth);

	/* 如果从非 RUNNING 状态进入 TERM，xfrpc 可能仍在运行 */
	pid = inst->xfrpc_pid;
	inst->xfrpc_pid = -1;
	if (pid > 0)
		xfrpc_stop(pid);

	log_info("shutting down");
	event_base_loopexit(inst->base, NULL);
}

/* ---- 定时器回调 ---- */

static void status_timer_cb(evutil_socket_t fd, short what, void *arg)
{
	inst_t *inst = arg;
	system_status_t st;
	int ret;

	(void)fd;
	(void)what;

	system_status_collect(&st, inst->cfg.local_if);

	ret = http_status(&inst->cfg, &inst->session, &st, inst->cfg.join_timeout);

	switch (ret) {
	case 0:
		sm_dispatch(inst, EV_STATUS_OK, NULL);
		break;
	case -ETIMEDOUT:
		sm_dispatch(inst, EV_STATUS_TIMEOUT, NULL);
		break;
	default:
		sm_dispatch(inst, EV_STATUS_FAIL, NULL);
		break;
	}
}

static void retry_timer_cb(evutil_socket_t fd, short what, void *arg)
{
	inst_t *inst = arg;

	(void)fd;
	(void)what;

	sm_dispatch(inst, EV_RETRY_EXPIRED, NULL);
}

static void xfrpc_restart_cb(evutil_socket_t fd, short what, void *arg)
{
	inst_t *inst = arg;
	pid_t pid;

	(void)fd;
	(void)what;

	/* 如果已离开 RUNNING 状态，不重启 */
	if (inst->current != ST_RUNNING)
		return;

	pid = xfrpc_spawn();
	if (pid > 0) {
		inst->xfrpc_pid = pid;
		log_info("xfrpc restarted, pid=%d", pid);
	} else {
		log_err("xfrpc restart failed");
	}
}
