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

#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/* MAC 转换：E4:67:1E:85:08:AF -> e4671e8508ae */
static void mac_normalize(const char *in, char *out, size_t sz)
{
	size_t j = 0;

	for (size_t i = 0; in[i] && j + 1 < sz; i++) {
		if (in[i] == ':')
			continue;
		out[j++] = tolower((unsigned char)in[i]);
	}
	out[j] = 0;
}

int skey_get_info(skey_info_t *info)
{
	char mac_raw[SKEY_MAC_STR_LEN];
	skey_err_t r;
	size_t pem_len;

	memset(info, 0, sizeof(*info));

	/* 1. 确保已初始化（幂等，已初始化时仅读校验） */
	r = skey_init();
	if (r != SKEY_OK) {
		log_err("skey_init failed: %d", r);
		return -1;
	}

	/* 2. 获取 device_id（UUID 的 BASE62 编码，22 字符）
	 * skey_get_device_id 可能不 null-terminate，显式保证结尾为 '\0' */
	r = skey_get_device_id(info->device_id);
	if (r != SKEY_OK) {
		log_err("skey_get_device_id failed: %d", r);
		return -1;
	}
	info->device_id[sizeof(info->device_id) - 1] = '\0';

	/* 3. 获取 MAC，转换为小写去冒号格式 */
	r = skey_get_mac(mac_raw);
	if (r != SKEY_OK) {
		log_err("skey_get_mac failed: %d", r);
		return -1;
	}
	mac_normalize(mac_raw, info->mac, sizeof(info->mac));

	/* 4. 获取 RSA-2048 公钥 PEM */
	pem_len = sizeof(info->pubkey);
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

/* ---- 双向身份认证封装（方案 D：公钥钉扎 + 根 CA 验服务器，v2.4+ libskey） ---- */

int skey_sign_data(const char *input, char *sig_b64, size_t sig_sz)
{
	skey_err_t r;
	size_t sig_len = sig_sz;

	if (!input || !sig_b64 || sig_sz == 0)
		return -1;

	memset(sig_b64, 0, sig_sz);
	r = skey_sign(input, sig_b64, &sig_len);
	if (r != SKEY_OK) {
		log_err("skey_sign failed: %d", r);
		return -1;
	}
	return 0;
}

/*
 * 验证服务器身份：skey_verify_cert 以 /etc/skey/ca.pem 根证书为信任锚，
 * 先校验 chain_pem（服务器叶子证书 + 工厂CA）链签名/有效期/层级，
 * 再用叶子证书公钥验证 input 的 Base64 签名。
 * 方案 D 下设备不出示证书，仅用此接口验证服务器。
 */
int skey_verify_peer(const char *input, const char *sig_b64,
		     const char *chain_pem)
{
	skey_err_t r;

	if (!input || !sig_b64 || !chain_pem)
		return -1;

	r = skey_verify_cert(input, sig_b64, chain_pem);
	if (r != SKEY_OK) {
		log_warn("skey_verify_cert failed: %d "
			 "(untrusted/expired/sig mismatch)", r);
		return -1;
	}
	return 0;
}

int skey_gen_nonce(char *out, size_t out_sz)
{
	unsigned char raw[32];
	size_t b64_len;

	if (!out || out_sz < SKEY_NONCE_B64_LEN)
		return -1;

	memset(out, 0, out_sz);

	if (RAND_bytes(raw, sizeof(raw)) != 1) {
		log_err("RAND_bytes failed");
		return -1;
	}

	/* 32 字节 -> 标准 Base64 44 字符（无换行） */
	b64_len = EVP_EncodeBlock((unsigned char *)out, raw, sizeof(raw));
	out[b64_len] = 0;
	return 0;
}

int skey_auth_materials_ready(void)
{
	/* 方案 D：根 CA 信任锚随固件发布，是验证服务器证书链的前提；
	 * 设备自身无需 CA 签发证书（身份由 join 钉扎公钥 + 私钥签名证明）。 */
	if (access(SKEY_CA_PATH_DEFAULT, F_OK) != 0) {
		log_err("CA trust anchor missing: %s", SKEY_CA_PATH_DEFAULT);
		return -1;
	}

	log_info("skey: root CA trust anchor ready (%s)",
		 SKEY_CA_PATH_DEFAULT);
	return 0;
}
