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
#ifndef XFRPC_LOADER_PROTOCOL_H
#define XFRPC_LOADER_PROTOCOL_H

#include <stddef.h>

#include "device_info.h"
#include "system_status.h"

/*
 * 双向认证：设备加入请求的签名材料。
 * 方案 D（公钥钉扎）：设备不出示证书，身份由请求中的 pub_key 公钥 +
 * 私钥签名证明；签名原文绑定 device_id/pubkey 摘要/nonce/ts（防抢注、防重放）。
 */
typedef struct {
	const char	*nonce;		/* 客户端 nonce（Base64，44 字符） */
	long		ts;		/* 请求 Unix 时间戳 */
	const char	*signature;	/* 对 join 签名原文的签名（Base64） */
} join_auth_t;

/* 服务器下发的时钟与时区信息（join/status body 及 /api/v1/time） */
#define TIME_INFO_TZ_LEN	64
#define TIME_INFO_NTP_LEN	512

typedef struct {
	long	server_time;			/* 服务器 Unix 时间戳，0=未下发 */
	char	tz_iana[TIME_INFO_TZ_LEN];	/* IANA 时区名，如 Asia/Shanghai */
	char	tz_posix[TIME_INFO_TZ_LEN];	/* POSIX TZ 串，如 CST-8 */
	char	ntp_servers[TIME_INFO_NTP_LEN];	/* NTP 列表，空格分隔 */
} time_info_t;

/* 加入成功响应解析结果 */
typedef struct {
	char	session_id[128];
	char	xfrpc_server_addr[64];
	int	xfrpc_server_port;
	char	ca_pub_key[1024];	/* 服务器 CA 公钥 PEM，可能为空 */
	int	frpc_mode;		/* 0=不启动 xfrpc（仅保活上报），1=启动；缺省为 1 */

	/* 双向认证字段（服务器下发） */
	char	server_cert[SKEY_CERT_LEN];	/* 服务器证书链 PEM */
	char	nonce[SKEY_NONCE_B64_LEN];	/* 服务器回显的客户端 nonce */
	char	signature[SKEY_SIG_LEN];	/* 服务器对响应的签名 */
	long	ts;				/* 服务器响应时间戳 */

	/*
	 * 云端下发的 RADIUS 对接参数（body.radius，可选）。
	 * 字段名与 local_config_http_api.md §4.2 可写字段一一对应；
	 * 缓冲大小与该接口字段长度上限一致，超长由 snprintf 截断，
	 * 推送前还会按接口规则做本地校验。
	 * 响应中无 radius 对象时全部为空/0，调用方据此跳过。
	 */
	char	radius_auth_server[24];		/* 主认证服务器地址 */
	char	radius_acct_server[24];		/* 主记账服务器地址 */
	char	radius_nas_ip[32];		/* NAS IP */
	char	radius_auth_secret[32];		/* 认证共享密钥 */
	char	radius_acct_secret[32];		/* 记账共享密钥 */
	int	radius_auth_port;		/* 认证端口 */
	int	radius_acct_port;		/* 记账端口 */
	char	tenant_org_id[64];		/* 租户 ID（body.radius，可选） */

	/* 服务器下发的时钟与时区（不参与签名原文） */
	time_info_t time_info;
} join_response_t;

/*
 * 构造加入请求 JSON body。
 * auth 非 NULL 时携带 nonce/ts/signature 双向认证字段。
 * 返回 malloc 分配的字符串，调用方负责 free。失败返回 NULL。
 */
char *protocol_build_join_request(const device_info_t *dev,
				  const join_auth_t *auth);

/*
 * 解析加入响应。
 * 返回 0 表示解析成功（不论 code 是否为 0）；
 * 返回 -1 表示 JSON 解析失败。
 * code 输出业务码；code == 0 时 resp 填充会话信息与认证字段。
 */
int protocol_parse_join_response(const char *body, join_response_t *resp,
				 int *code, char *msg, size_t msg_sz);

/*
 * 构造状态请求 JSON body。
 * sess 提供 session_id；ts/signature 为双向认证材料。
 * 返回 malloc 分配的字符串，调用方负责 free。失败返回 NULL。
 */
char *protocol_build_status_request(const system_status_t *st,
				    const char *session_id,
				    long ts, const char *signature);

/*
 * 解析状态响应。
 * srv_ts/signature 输出服务器时间戳与签名（可为 NULL 不提取）。
 * ti 输出响应 body 中的时钟/时区信息（可为 NULL 不提取）。
 * 返回 0 成功，-1 JSON 解析失败。
 * code 输出业务码。
 */
int protocol_parse_status_response(const char *body, int *code,
				   char *msg, size_t msg_sz,
				   long *srv_ts,
				   char *signature, size_t sig_sz,
				   time_info_t *ti);

/*
 * 解析免鉴权引导接口 /api/v1/time 的响应（body 或顶层字段）。
 * 返回 0 成功，-1 JSON 解析失败。
 */
int protocol_parse_time_response(const char *body, time_info_t *ti);

/*
 * ---- 双向认证签名原文（canonical text）与辅助 ----
 * 签名原文为多行文本，'\n' 分隔、无尾部换行；两端必须逐字节一致。
 * 输出缓冲区建议 >= 1024。返回 0 成功，-1 失败。
 */

/*
 * join 请求：xfrpc-auth-v1 / join / device_id / mac / nonce / ts /
 *           sha256(pubkey_pem)
 * 末行绑定本次注册的设备公钥摘要（方案 D 公钥钉扎：证明持有对应私钥，
 * 防抢注），服务器按请求体 pub_key 字段取同值校验。
 */
int protocol_canon_join_req(const device_info_t *dev,
			    const char *nonce, long ts,
			    char *out, size_t out_sz);

/* join 响应：xfrpc-auth-v1 / join-resp / device_id / nonce / ts /
 *           session_id / xfrpc_addr / xfrpc_port */
int protocol_canon_join_resp(const char *device_id,
			     const join_response_t *resp,
			     char *out, size_t out_sz);

/* status 请求：xfrpc-auth-v1 / status / session_id / ts */
int protocol_canon_status_req(const char *session_id, long ts,
			      char *out, size_t out_sz);

/* status 响应：xfrpc-auth-v1 / status-resp / session_id / ts / code */
int protocol_canon_status_resp(const char *session_id, long ts, int code,
			       char *out, size_t out_sz);

/*
 * auth 请求：xfrpc-auth-v1 / auth / session_id / ts /
 *           sha256(username) / sha256(password) / sha256(credentials)
 * 字段为 NULL 时按空串参与哈希。
 */
int protocol_canon_auth_req(const char *session_id, long ts,
			    const char *username, const char *password,
			    const char *credentials,
			    char *out, size_t out_sz);

/* auth 响应：xfrpc-auth-v1 / auth-resp / session_id / ts / code */
int protocol_canon_auth_resp(const char *session_id, long ts, int code,
			     char *out, size_t out_sz);

/*
 * 计算字符串的 SHA-256，输出 64 字符小写十六进制（out >= 65）。
 * in 为 NULL 时按空串计算。返回 0 成功，-1 失败。
 */
int protocol_sha256_hex(const char *in, char *out_hex);

#endif /* XFRPC_LOADER_PROTOCOL_H */
