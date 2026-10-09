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
#include "auth_local.h"
#include "skey.h"
#include "log.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/wait.h>
#include <curl/curl.h>
#include <json-c/json.h>

#define LOCALPASSWD_LEN     16
#define LUCI_USERNAME       "root"
#define LUCI_URL            "http://127.0.0.1:8000"
#define UBUS_RPC_PATH       "/ubus"
/* UBUS 未认证会话 ID（32 个 0），session.login 请求的 params[0] */
#define UBUS_NULL_SID       "00000000000000000000000000000000"

/* ---- curl 响应缓冲区 ---- */

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

/* ---- HTTP POST（luci-mod-rpc 用 POST JSON-RPC 请求） ---- */

static int http_post(const char *url, const char *body,
		     int timeout_sec, struct resp_buf *resp)
{
	CURL *curl;
	CURLcode rc;
	long http_code = 0;
	struct curl_slist *hdrs = NULL;

	curl = curl_easy_init();
	if (!curl)
		return -1;

	hdrs = curl_slist_append(hdrs, "Content-Type: application/json");

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)timeout_sec);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long)timeout_sec);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	/* HTTPS 跳过证书校验（服务端可能使用自签名证书） */
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	
	rc = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	curl_slist_free_all(hdrs);
	curl_easy_cleanup(curl);

	if (rc != CURLE_OK) {
		log_err("curl error: %s", curl_easy_strerror(rc));
		return -1;
	}
	if (http_code < 200 || http_code >= 300) {
		log_warn("http %s returned status %ld", url, http_code);
		return -1;
	}
	return 0;
}

/* ---- 随机密码生成 ---- */

static int gen_random_password(char *buf, size_t buf_sz)
{
	const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	size_t i;
	FILE *f;

	f = fopen("/dev/urandom", "rb");
	if (!f) {
		log_err("cannot open /dev/urandom");
		return -1;
	}

	for (i = 0; i < LOCALPASSWD_LEN && i < buf_sz - 1; i++) {
		int c = fgetc(f);
		buf[i] = charset[c % (sizeof(charset) - 1)];
	}
	buf[i] = 0;
	fclose(f);
	return 0;
}

/* ---- 密码文件读写（skey 加密/解密） ---- */

static int save_encrypted_password(const char *plaintext)
{
	char ct_b64[SKEY_CT_B64_LEN];
	FILE *f;

	if (skey_encrypt_password(plaintext, ct_b64, sizeof(ct_b64)) < 0) {
		log_err("localpasswd: encrypt failed");
		return -1;
	}

	f = fopen(LOCALPASSWD_FILE, "w");
	if (!f) {
		log_err("localpasswd: cannot write %s: %s",
			LOCALPASSWD_FILE, strerror(errno));
		return -1;
	}
	fprintf(f, "%s\n", ct_b64);
	fclose(f);

	log_info("localpasswd: saved to %s", LOCALPASSWD_FILE);
	return 0;
}

static int load_encrypted_password(char *password, size_t pwd_sz)
{
	FILE *f;
	char ct_b64[SKEY_CT_B64_LEN];
	size_t n;

	f = fopen(LOCALPASSWD_FILE, "r");
	if (!f)
		return -1;

	n = fread(ct_b64, 1, sizeof(ct_b64) - 1, f);
	fclose(f);
	if (n == 0) {
		log_err("localpasswd: file empty");
		return -1;
	}
	ct_b64[n] = 0;
	/* 去除尾部换行 */
	while (n > 0 && (ct_b64[n - 1] == '\n' || ct_b64[n - 1] == '\r'))
		ct_b64[--n] = 0;

	if (skey_decrypt_password(ct_b64, password, pwd_sz) < 0) {
		log_err("localpasswd: decrypt failed");
		return -1;
	}
	return 0;
}

/* ---- 通过 passwd 设置 root 密码 ---- */

/*
 * 用 passwd 修改用户密码：密码经 stdin 传入（需输入两遍确认），
 * 不经过 shell 解析、不出现在命令行（避免 ps 泄露与被特殊字符破坏）。
 * 空密码时用 passwd -d 删除密码（等价于写入空值）。
 * 注意：BusyBox 通常不提供 chpasswd，故此处不能用 chpasswd。
 * 返回 0 表示成功，-1 表示调用或执行失败。
 */
static int set_user_password(const char *user, const char *new_password)
{
	FILE *fp;
	int status;
	int is_empty = (!new_password || !new_password[0]);
	char cmd[128];
	const char *p;

	if (!user || !user[0]) {
		log_err("set_user_password: empty user name");
		return -1;
	}

	/* 用户名会被拼进 shell 命令，限定字符集避免注入 */
	for (p = user; *p; p++) {
		if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
		      (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')) {
			log_err("set_user_password: invalid user name");
			return -1;
		}
	}

	if (is_empty)
		snprintf(cmd, sizeof(cmd), "passwd -d %s", user);
	else
		snprintf(cmd, sizeof(cmd), "passwd %s", user);

	log_info("set_user_password: executing %s for user %s",
		 is_empty ? "passwd -d" : "passwd", user);

	fp = popen(cmd, "w");
	if (!fp) {
		log_err("set_user_password: popen failed: %s", strerror(errno));
		return -1;
	}

	if (!is_empty &&
	    fprintf(fp, "%s\n%s\n", new_password, new_password) < 0) {
		log_err("set_user_password: write to passwd failed");
		pclose(fp);
		return -1;
	}

	status = pclose(fp);

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		log_info("set_user_password: succeeded for user %s", user);
		return 0;
	}

	log_err("set_user_password: passwd abnormal exit (status=%d)", status);
	return -1;
}

/* ---- 公开接口 ---- */

/*
 * 获取 LuCI 密码：
 *   - 如果 /etc/config/localpasswd 存在，读取并用 skey 私钥解密
 *   - 如果不存在或解密失败，使用 DEFAULT_LUCI_PASSWORD（root 空密码），
 *     并通过 reason 输出 AUTH_LPWD_NOT_INIT / AUTH_LPWD_DECRYPT_FAIL
 */
int auth_local_get_password_ex(char *password, size_t pwd_sz, int *reason)
{
	if (reason)
		*reason = AUTH_LPWD_OK;

	if (access(LOCALPASSWD_FILE, F_OK) == 0) {
		log_info("localpasswd: file %s exists, loading and decrypting",
			 LOCALPASSWD_FILE);
		if (load_encrypted_password(password, pwd_sz) == 0) {
			log_info("localpasswd: decrypted ok (len=%zu)",
				 strlen(password));
			if (reason)
				*reason = AUTH_LPWD_OK;
			return 0;
		}
		log_warn("localpasswd: decrypt failed (skey mismatch or corrupted "
			 "file?), falling back to empty password");
		if (reason)
			*reason = AUTH_LPWD_DECRYPT_FAIL;
	} else {
		log_info("localpasswd: file %s not found (device not initialized "
			 "yet), falling back to empty password",
			 LOCALPASSWD_FILE);
		if (reason)
			*reason = AUTH_LPWD_NOT_INIT;
	}

	/* 使用默认密码（空密码，仅当系统 root 密码也为空时才能登录成功） */
	snprintf(password, pwd_sz, "%s", DEFAULT_LUCI_PASSWORD);
	return 0;
}

int auth_local_get_password(char *password, size_t pwd_sz)
{
	return auth_local_get_password_ex(password, pwd_sz, NULL);
}

/*
 * 轮换 LuCI 密码（原子操作）：
 *   - 生成 16 字符随机密码
 *   - 通过 passwd 修改系统 root 密码为新密码
 *   - 用 skey 公钥加密后保存到 /etc/config/localpasswd
 *
 * 原子性保证：修改系统密码与写 localpasswd 必须同时成功。
 * 顺序为先改系统密码、成功后落盘加密文件；若落盘失败，则回滚系统密码，
 * 尽可能保持两者一致（任一步失败整体判为失败）。
 */
int auth_local_rotate_password(char *new_password, size_t pwd_sz)
{
	char generated[LOCALPASSWD_LEN + 1];
	char old_pwd[LOCALPASSWD_LEN + 1];
	char *out = new_password ? new_password : generated;
	size_t out_sz = new_password ? pwd_sz : sizeof(generated);

	log_info("localpasswd: rotating password...");

	/* 0. 记录当前密码，用于落盘失败时回滚系统密码 */
	if (auth_local_get_password(old_pwd, sizeof(old_pwd)) < 0) {
		log_err("localpasswd rotate: step0 FAILED: cannot read current password");
		return -1;
	}

	/* 1. 生成随机密码 */
	if (gen_random_password(out, out_sz) < 0) {
		log_err("localpasswd rotate: step1 FAILED: gen random password");
		return -1;
	}

	/* 2. 先修改系统 root 密码（未落盘，失败即整体失败） */
	log_info("localpasswd rotate: step2: setting root password via passwd");
	if (set_user_password(LUCI_USERNAME, out) < 0) {
		log_err("localpasswd rotate: step2 FAILED: set root password");
		return -1;
	}
	log_info("localpasswd rotate: step2 OK: root password changed");

	/* 3. 落盘加密文件；失败则回滚系统密码，保持两者一致 */
	log_info("localpasswd rotate: step3: encrypting and saving to %s",
		 LOCALPASSWD_FILE);
	if (save_encrypted_password(out) < 0) {
		log_err("localpasswd rotate: step3 FAILED: save encrypted password, "
			"rolling back system password");
		if (set_user_password(LUCI_USERNAME, old_pwd) < 0)
			log_err("localpasswd rotate: rollback FAILED: system password "
				"not restored, device may require manual reset");
		return -1;
	}
	log_info("localpasswd rotate: step3 OK: saved to %s",
		 LOCALPASSWD_FILE);

	log_info("localpasswd: rotation complete");
	return 0;
}

/*
 * 使用指定用户名/明文密码设置登录凭证（原子操作）：
 *   - 通过 passwd 将指定用户的系统密码设为明文密码
 *   - 用 skey 公钥加密后写入 /etc/config/localpasswd
 * 原子性保证与轮换相同：先改系统密码、成功后落盘，落盘失败回滚。
 * 用于"修改本机密码"开关关闭时，用配置默认用户名/密码锁死用户。
 */
int auth_local_set_password(const char *username, const char *password)
{
	char old_pwd[64];

	if (!username || !username[0] || !password || !password[0]) {
		log_err("localpasswd set: invalid username or empty password");
		return -1;
	}

	/* 0. 记录当前密码，用于落盘失败时回滚 */
	if (auth_local_get_password(old_pwd, sizeof(old_pwd)) < 0) {
		log_err("localpasswd set: step0 FAILED: cannot read current password");
		return -1;
	}

	/* 1. 先修改指定用户系统密码（未落盘，失败即整体失败） */
	log_info("localpasswd set: setting %s password via passwd (len=%zu)",
		 username, strlen(password));
	if (set_user_password(username, password) < 0) {
		log_err("localpasswd set: step1 FAILED: set %s password", username);
		return -1;
	}

	/* 2. 落盘加密文件；失败则回滚系统密码 */
	if (save_encrypted_password(password) < 0) {
		log_err("localpasswd set: step2 FAILED: save encrypted password, "
			"rolling back %s password", username);
		if (set_user_password(username, old_pwd) < 0)
			log_err("localpasswd set: rollback FAILED: system password "
				"not restored, device may require manual reset");
		return -1;
	}
	log_info("localpasswd set: credentials set for %s", username);
	return 0;
}

/* ---- UBUS session.login 登录 ---- */
/* 设备 OpenWrt 已卸载所有 LuCI 模块，/cgi-bin/luci/rpc/auth 不存在（返回 500）；
 * 改用 UBUS JSON-RPC session.login 获取 ubus_rpc_session，该 sid 可直接
 * 作为后续 /ubus 业务调用（system.board / luci-rpc.* / iwinfo.* 等）的
 * params[0] 凭据。协议参考 cloud_ac tentant-mng ubusproxy.Client.login。 */

int auth_local_ubus_login(const char *password, luci_token_t *token)
{
	char url[512];
	char body[768];
	struct resp_buf rbuf = { 0 };
	struct json_object *root, *jresult, *jerror, *jcode, *jdata, *jsid, *jtimeout;
	int pwd_len = password ? strlen(password) : 0;
	int ubus_code = 0;
	int timeout = 300;

	memset(token, 0, sizeof(*token));

	snprintf(url, sizeof(url), "%s%s", LUCI_URL, UBUS_RPC_PATH);

	/* UBUS JSON-RPC session.login：
	 *   {"jsonrpc":"2.0","id":1,"method":"call",
	 *    "params":["<nullSID>","session","login",
	 *              {"username":"root","password":"<password>"}]}
	 * 成功返回：
	 *   {"jsonrpc":"2.0","id":1,"result":[0,{"ubus_rpc_session":"<sid>","timeout":300,...}]}
	 * 失败返回：
	 *   {"jsonrpc":"2.0","id":1,"result":[6,null]}  （6=PERMISSION_DENIED，密码错）
	 *   {"jsonrpc":"2.0","id":1,"error":{"code":-32002,"message":"Access denied"}} */
	snprintf(body, sizeof(body),
		 "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"call\","
		 "\"params\":[\"%s\",\"session\",\"login\","
		 "{\"username\":\"%s\",\"password\":\"%s\"}]}",
		 UBUS_NULL_SID, LUCI_USERNAME, password);

	log_info("ubus login: POST %s user=%s password_len=%d",
		 url, LUCI_USERNAME, pwd_len);

	if (http_post(url, body, 5, &rbuf) < 0) {
		log_err("ubus login: http POST failed (url=%s)", url);
		resp_buf_free(&rbuf);
		return -1;
	}

	log_info("ubus login: <- HTTP resp_len=%zu, body(%.256s)",
		 rbuf.size, rbuf.data ? rbuf.data : "(empty)");

	root = json_tokener_parse(rbuf.data ? rbuf.data : "null");
	resp_buf_free(&rbuf);

	if (!root) {
		log_err("ubus login: parse response json failed");
		return -1;
	}

	if (json_object_is_type(root, json_type_null)) {
		json_object_put(root);
		log_warn("ubus login: response is null (access denied / bad password)");
		return -1;
	}

	/* 检查 JSON-RPC 层 error 字段（如 -32002 Access denied） */
	if (json_object_object_get_ex(root, "error", &jerror) &&
	    !json_object_is_type(jerror, json_type_null)) {
		log_warn("ubus login: rpc error=%s",
			 json_object_get_string(jerror));
		json_object_put(root);
		return -1;
	}

	/* result 是数组：[code, data] */
	if (!json_object_object_get_ex(root, "result", &jresult) ||
	    !json_object_is_type(jresult, json_type_array)) {
		log_warn("ubus login: result missing or not array");
		json_object_put(root);
		return -1;
	}

	jcode = json_object_array_get_idx(jresult, 0);
	if (!jcode) {
		log_warn("ubus login: result[0] (code) missing");
		json_object_put(root);
		return -1;
	}
	ubus_code = json_object_get_int(jcode);
	if (ubus_code != 0) {
		/* 6 = PERMISSION_DENIED（密码错/会话拒绝） */
		log_warn("ubus login: ubus status=%d (wrong password?)", ubus_code);
		json_object_put(root);
		return -1;
	}

	jdata = json_object_array_get_idx(jresult, 1);
	if (!jdata ||
	    !json_object_object_get_ex(jdata, "ubus_rpc_session", &jsid)) {
		log_warn("ubus login: ubus_rpc_session missing");
		json_object_put(root);
		return -1;
	}

	snprintf(token->token, sizeof(token->token), "%s",
		 json_object_get_string(jsid));
	token->obtained_at = time(NULL);

	if (json_object_object_get_ex(jdata, "timeout", &jtimeout))
		timeout = json_object_get_int(jtimeout);
	token->expires = timeout > 0 ? timeout : 300;
	token->valid = 1;
	json_object_put(root);

	log_info("ubus login: SUCCESS sid=%.16s... (len=%zu, ttl=%ds)",
		 token->token, strlen(token->token), token->expires);
	return 0;
}
