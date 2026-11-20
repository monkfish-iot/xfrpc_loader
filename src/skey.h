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
#ifndef XFRPC_LOADER_SKEY_H
#define XFRPC_LOADER_SKEY_H

#include <stddef.h>

#include <skey.h>	/* SKEY_DEVICE_ID_BUF, SKEY_MAC_STR_LEN, SKEY_CERT_CHAIN_MAX,
			 * skey_err_t 等（libskey 静态库公共头文件） */

/* 派生常量（供本程序各缓冲统一使用） */
#define SKEY_DEV_ID_LEN		SKEY_DEVICE_ID_BUF	/* device_id 缓冲区大小 */
#define SKEY_MAC_LEN		13			/* 12 hex chars + '\0' */
#define SKEY_PUBKEY_LEN		SKEY_PUBKEY_PEM_MAX	/* RSA-2048 公钥 PEM + '\0' */
#define SKEY_CT_B64_LEN		SKEY_ENC_B64_MAX	/* 加密输出 Base64 缓冲区 */
#define SKEY_PT_BUF_LEN		SKEY_DEC_BUF_MAX	/* 解密输出缓冲区 */
#define SKEY_CERT_LEN		SKEY_CERT_CHAIN_MAX	/* 证书链 PEM 缓冲区 */
#define SKEY_SIG_LEN		SKEY_SIG_B64_MAX	/* Base64 签名缓冲区 */
#define SKEY_NONCE_B64_LEN	45			/* 32 字节随机数 -> 44 字符 Base64 + '\0' */

typedef struct {
	char	device_id[SKEY_DEV_ID_LEN];	/* BASE62 编码的 device_id */
	char	mac[SKEY_MAC_LEN];		/* lowercase, no colons, e.g. "e4671e8508ae" */
	char	pubkey[SKEY_PUBKEY_LEN];	/* RSA-2048 公钥 PEM */
} skey_info_t;

/*
 * 初始化 skey 并获取 device_id、MAC 和 RSA 公钥。
 * device_id/pubkey 取自 pid 分区，MAC 从 Factory 分区读取并转换为
 * 小写去冒号格式。
 * 返回 0 成功，-1 失败。
 */
int skey_get_info(skey_info_t *info);

/*
 * 使用设备 RSA 公钥加密明文。
 * ct_b64 输出 Base64 密文字符串。
 * 返回 0 成功，-1 失败。
 */
int skey_encrypt_password(const char *plaintext, char *ct_b64, size_t ct_sz);

/*
 * 使用设备 RSA 私钥解密 Base64 密文。
 * plaintext 输出明文字符串。
 * 返回 0 成功，-1 失败。
 */
int skey_decrypt_password(const char *ct_b64, char *plaintext, size_t pt_sz);

/*
 * ---- 双向身份认证接口（方案 D：公钥钉扎 + 根 CA 验服务器） ----
 *   - 设备身份：join 时上报 RSA 公钥 PEM（pub_key），并用设备私钥对请求
 *     签名（skey_sign_data），服务器钉扎公钥后凭签名验明设备身份；
 *     设备不需要 CA 签发的证书，私钥始终在 pid 分区内。
 *   - 验证服务器：以随固件发布的根 CA /etc/skey/ca.pem 为信任锚，
 *     校验服务器下发的证书链并验签（skey_verify_peer）。
 */

/*
 * 用设备 RSA 私钥对 input 做 SHA-256 + RSA 签名（PKCS#1 v1.5），
 * sig_b64 输出标准 Base64 签名。
 * 返回 0 成功，-1 失败。
 */
int skey_sign_data(const char *input, char *sig_b64, size_t sig_sz);

/*
 * 以 /etc/skey/ca.pem 根证书为信任锚，校验 chain_pem 证书链
 * （链签名/有效期/basicConstraints），通过后用叶子证书公钥验证
 * input 的 Base64 签名 sig_b64。
 * 返回 0 链受信且验签通过，-1 失败（不受信/过期/签名不符/材料缺失）。
 */
int skey_verify_peer(const char *input, const char *sig_b64,
		     const char *chain_pem);

/*
 * 生成 32 字节随机数并编码为标准 Base64（44 字符），用于防重放 nonce。
 * out 缓冲区 >= SKEY_NONCE_B64_LEN。
 * 返回 0 成功，-1 失败。
 */
int skey_gen_nonce(char *out, size_t out_sz);

/*
 * 预检双向认证材料是否就绪：根 CA 信任锚 /etc/skey/ca.pem 存在
 * （方案 D 下设备无需 CA 签发证书，仅需根 CA 验证服务器）。
 * 返回 0 就绪，-1 缺失（调用方应致命退出并提示烧录材料）。
 */
int skey_auth_materials_ready(void);

#endif /* XFRPC_LOADER_SKEY_H */
