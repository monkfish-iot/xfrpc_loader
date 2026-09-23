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
#include "skey.h"
#include "log.h"

#ifdef LOCAL_SKEY
/* ==================== LOCAL_SKEY 模式：本地文件密钥 ==================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdint.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

/* 本地密钥文件路径 */
#define SKEY_DIR         "/etc/config/skey"
#define SKEY_PRIV_KEY    SKEY_DIR "/private_key.pem"
#define SKEY_PUB_KEY     SKEY_DIR "/public_key.pem"
#define SKEY_DEV_ID_FILE SKEY_DIR "/device_id"
#define SKEY_GEN_SCRIPT  "/usr/bin/skey_gen.sh"

/* ---- 文件读取辅助 ---- */

static int read_file(const char *path, char *buf, size_t sz)
{
	FILE *f = fopen(path, "r");
	if (!f)
		return -1;
	size_t n = fread(buf, 1, sz - 1, f);
	fclose(f);
	buf[n] = 0;
	/* 去除尾部换行 */
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		buf[--n] = 0;
	return 0;
}

static int file_exists(const char *path)
{
	return access(path, F_OK) == 0;
}

/* ---- 密钥文件生成（调用外部脚本） ---- */

static int ensure_skey_files(void)
{
	/* 文件已存在，无需生成 */
	if (file_exists(SKEY_DEV_ID_FILE) &&
	    file_exists(SKEY_PUB_KEY) &&
	    file_exists(SKEY_PRIV_KEY))
		return 0;

	log_info("skey: files missing, calling %s", SKEY_GEN_SCRIPT);

	int rc = system(SKEY_GEN_SCRIPT);
	if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0) {
		log_err("skey_gen.sh failed (rc=%d)", rc);
		return -1;
	}

	/* 验证文件已生成 */
	if (!file_exists(SKEY_DEV_ID_FILE) ||
	    !file_exists(SKEY_PUB_KEY) ||
	    !file_exists(SKEY_PRIV_KEY)) {
		log_err("skey: files not found after generation");
		return -1;
	}
	return 0;
}

/* ---- RSA 密钥加载 ---- */

static EVP_PKEY *load_pubkey_pem(void)
{
	BIO *bio = BIO_new_file(SKEY_PUB_KEY, "r");
	if (!bio)
		return NULL;

	EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	BIO_free(bio);
	return pkey;
}

static EVP_PKEY *load_privkey_pem(void)
{
	BIO *bio = BIO_new_file(SKEY_PRIV_KEY, "r");
	if (!bio)
		return NULL;

	EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	BIO_free(bio);
	return pkey;
}

/* ---- Base64 编解码 ---- */

static int b64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_sz)
{
	size_t b64_len = 4 * ((in_len + 2) / 3);

	if (b64_len + 1 > out_sz)
		return -1;

	EVP_EncodeBlock((unsigned char *)out, in, in_len);
	out[b64_len] = 0;
	return 0;
}

/*
 * EVP_DecodeBlock 的解码临时缓冲上限。
 * 注意：EVP_DecodeBlock 不剥离 '=' padding——每 4 个字符固定写出
 * 3 字节，返回长度按 3 的倍数向上取整。RSA-2048 密文 256 字节的
 * Base64 为 344 字符（结尾 "=="），EVP_DecodeBlock 会写出 258 字节，
 * 比真实密文多 2 字节。不能直接写进调用方 256 字节的缓冲，否则
 * 越界写 2 字节，可能踩坏栈帧/栈金丝雀导致进程 abort，故临时缓冲
 * 按向上取整到 3 的倍数分配（258），解码后只拷回真实长度。
 */
#define B64_DECODE_TMP_MAX	(((SKEY_DEC_BUF_MAX + 2) / 3) * 3)

static int b64_decode(const char *in, uint8_t *out, size_t out_sz, size_t *out_len)
{
	int in_len = (int)strlen(in);
	int n, pad = 0;
	int expected;
	uint8_t tmp[B64_DECODE_TMP_MAX];

	if (in_len <= 0 || in_len % 4 != 0)
		return -1;

	/* 计算等号 padding 数量 */
	if (in[in_len - 1] == '=') pad++;
	if (in_len >= 2 && in[in_len - 2] == '=') pad++;

	/* 去掉 padding 后的真实解码输出长度 */
	expected = in_len / 4 * 3 - pad;
	if (expected <= 0 || expected > (int)out_sz)
		return -1;
	/* EVP_DecodeBlock 实际写入 in_len/4*3 字节，超长输入也不能写进 tmp */
	if (in_len / 4 * 3 > B64_DECODE_TMP_MAX)
		return -1;

	/* 使用 EVP_DecodeBlock（与 b64_encode 的 EVP_EncodeBlock 对称），
	 * 避免 BIO_f_base64 流式解码的内部缓冲问题导致返回部分结果。
	 * 先写入临时缓冲，再按真实长度拷回，杜绝 padding 造成的越界写。 */
	n = EVP_DecodeBlock(tmp, (const unsigned char *)in, in_len);
	if (n < expected)
		return -1;

	memcpy(out, tmp, (size_t)expected);
	*out_len = (size_t)expected;
	return 0;
}

/* ---- 对外接口 ---- */

int skey_get_info(skey_info_t *info)
{
	memset(info, 0, sizeof(*info));

	/* 1. 确保密钥文件存在（不存在则调用脚本生成） */
	if (ensure_skey_files() < 0) {
		log_err("skey: cannot ensure key files");
		return -1;
	}

	/* 2. 读取 device_id */
	if (read_file(SKEY_DEV_ID_FILE, info->device_id, sizeof(info->device_id)) < 0) {
		log_err("skey: cannot read device_id: %s", strerror(errno));
		return -1;
	}

	/* 3. 读取公钥 PEM */
	if (read_file(SKEY_PUB_KEY, info->pubkey, sizeof(info->pubkey)) < 0) {
		log_err("skey: cannot read public_key: %s", strerror(errno));
		return -1;
	}

	/* 4. MAC 不在此获取，由 device_info.c 从 local_if 读取 */

	log_info("skey: device_id=%s pubkey_len=%zu",
		 info->device_id, strlen(info->pubkey));
	return 0;
}

int skey_encrypt_password(const char *plaintext, char *ct_b64, size_t ct_sz)
{
	EVP_PKEY *pkey;
	EVP_PKEY_CTX *ctx;
	uint8_t ct[SKEY_DEC_BUF_MAX];	/* RSA-2048 输出 256 字节 */
	size_t ct_len;

	if (!plaintext || !ct_b64 || ct_sz == 0)
		return -1;

	memset(ct_b64, 0, ct_sz);

	/* 加载公钥 */
	pkey = load_pubkey_pem();
	if (!pkey) {
		log_err("skey: cannot load public key");
		return -1;
	}

	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	EVP_PKEY_free(pkey);
	if (!ctx) {
		log_err("skey: EVP_PKEY_CTX_new failed");
		return -1;
	}

	/* RSA PKCS#1 v1.5 加密 */
	if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
		log_err("skey: encrypt_init failed");
		EVP_PKEY_CTX_free(ctx);
		return -1;
	}

	ct_len = sizeof(ct);
	if (EVP_PKEY_encrypt(ctx, ct, &ct_len,
			     (const unsigned char *)plaintext,
			     strlen(plaintext)) <= 0) {
		log_err("skey: EVP_PKEY_encrypt failed");
		EVP_PKEY_CTX_free(ctx);
		return -1;
	}

	EVP_PKEY_CTX_free(ctx);

	/* Base64 编码输出 */
	if (b64_encode(ct, ct_len, ct_b64, ct_sz) < 0) {
		log_err("skey: base64 encode overflow");
		return -1;
	}
	return 0;
}

int skey_decrypt_password(const char *ct_b64, char *plaintext, size_t pt_sz)
{
	EVP_PKEY *pkey;
	EVP_PKEY_CTX *ctx;
	uint8_t ct[SKEY_DEC_BUF_MAX];
	size_t ct_len, pt_len;

	if (!ct_b64 || !plaintext || pt_sz == 0)
		return -1;

	memset(plaintext, 0, pt_sz);

	/* Base64 解码 */
	if (b64_decode(ct_b64, ct, sizeof(ct), &ct_len) < 0) {
		log_err("skey: base64 decode failed (in_len=%zu)",
			strlen(ct_b64));
		return -1;
	}
	log_info("skey: b64 decoded ok (in_len=%zu, ct_len=%zu)",
		 strlen(ct_b64), ct_len);

	/* 加载私钥 */
	pkey = load_privkey_pem();
	if (!pkey) {
		log_err("skey: cannot load private key");
		return -1;
	}

	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	EVP_PKEY_free(pkey);
	if (!ctx) {
		log_err("skey: EVP_PKEY_CTX_new failed");
		return -1;
	}

	/* RSA PKCS#1 v1.5 解密 */
	if (EVP_PKEY_decrypt_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
		log_err("skey: decrypt_init failed");
		EVP_PKEY_CTX_free(ctx);
		return -1;
	}

	pt_len = pt_sz;
	if (EVP_PKEY_decrypt(ctx, (unsigned char *)plaintext, &pt_len,
			     ct, ct_len) <= 0) {
		log_err("skey: EVP_PKEY_decrypt failed");
		EVP_PKEY_CTX_free(ctx);
		return -1;
	}

	EVP_PKEY_CTX_free(ctx);

	plaintext[pt_len] = 0;
	return 0;
}

#else
/* ==================== 静态库模式：libskey 包装 ==================== */

#include <skey.h>		/* libskey 系统头文件 */
#include <string.h>
#include <ctype.h>

/* MAC 转换：E4:67:1E:85:08:AF -> e4671e8508ae */
static void mac_normalize(const char *in, char *out, size_t sz)
{
	size_t i, j = 0;

	for (i = 0; in[i] && j < sz - 1; i++) {
		if (in[i] != ':' && in[i] != '-')
			out[j++] = tolower((unsigned char)in[i]);
	}
	out[j] = 0;
}

int skey_get_info(skey_info_t *info)
{
	char mac_raw[SKEY_MAC_STR_LEN];
	skey_err_t r;

	memset(info, 0, sizeof(*info));

	/* 1. 确保已初始化（幂等，已初始化时仅读校验） */
	r = skey_init();
	if (r != SKEY_OK) {
		log_err("skey_init failed: %d", r);
		return -1;
	}

	/* 2. 获取 device_id（UUID 的 BASE62 编码，22 字符）
	 * skey_get_device_id 可能不 null-terminate，显式保证结尾为 '\0' */
	memset(info->device_id, 0, sizeof(info->device_id));
	r = skey_get_device_id(info->device_id);
	if (r != SKEY_OK) {
		log_err("skey_get_device_id failed: %d", r);
		return -1;
	}
	info->device_id[SKEY_DEV_ID_LEN - 1] = '\0';

	/* 3. 获取 MAC，转换为小写去冒号格式 */
	r = skey_get_mac(mac_raw);
	if (r != SKEY_OK) {
		log_err("skey_get_mac failed: %d", r);
		return -1;
	}
	mac_normalize(mac_raw, info->mac, sizeof(info->mac));

	/* 4. 获取 RSA-2048 公钥 PEM */
	size_t pem_len = sizeof(info->pubkey);
	memset(info->pubkey, 0, sizeof(info->pubkey));
	r = skey_get_pubkey_pem(info->pubkey, &pem_len);
	if (r != SKEY_OK) {
		log_err("skey_get_pubkey_pem failed: %d", r);
		return -1;
	}

	log_info("skey: device_id=%s mac=%s pubkey_len=%zu",
		 info->device_id, info->mac, pem_len);
	return 0;
}

int skey_encrypt_password(const char *plaintext, char *ct_b64, size_t ct_sz)
{
	skey_err_t r;
	size_t ct_len = ct_sz;

	if (!plaintext || !ct_b64 || ct_sz == 0)
		return -1;

	memset(ct_b64, 0, ct_sz);
	r = skey_encrypt(plaintext, ct_b64, &ct_len);
	if (r != SKEY_OK) {
		log_err("skey_encrypt failed: %d", r);
		return -1;
	}
	return 0;
}

int skey_decrypt_password(const char *ct_b64, char *plaintext, size_t pt_sz)
{
	skey_err_t r;
	size_t pt_len = pt_sz;

	if (!ct_b64 || !plaintext || pt_sz == 0)
		return -1;

	memset(plaintext, 0, pt_sz);
	r = skey_decrypt(ct_b64, plaintext, &pt_len);
	if (r != SKEY_OK) {
		log_err("skey_decrypt failed: %d", r);
		return -1;
	}
	return 0;
}

#endif /* LOCAL_SKEY */
