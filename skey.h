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

#ifdef LOCAL_SKEY
/* ---- LOCAL_SKEY 模式：自定义常量，不依赖 libskey 头文件 ---- */

#define SKEY_MAGIC_LEN      4
#define SKEY_VERSION        1
#define SKEY_IV_LEN         16
#define SKEY_AES_KEY_LEN    16
#define SKEY_UUID_LEN       16
#define SKEY_RSA_BITS       2048
#define SKEY_PUBKEY_AREA    300   /* RSA-2048 SubjectPublicKeyInfo DER 约 294 字节 */
#define SKEY_PRIVKEY_AREA   1400  /* RSA-2048 PKCS#8 PrivateKeyInfo DER 约 1218 字节 */
#define SKEY_HMAC_LEN       32
#define SKEY_DEVICE_ID_LEN  22    /* BASE62 编码长度 */
#define SKEY_UUID_B64_LEN   22    /* URL-safe Base64 编码长度 */

/* struct 总长 = 头(32) + 加密主体(1728) + hmac(32) = 1792 */
#define SKEY_BODY_LEN       1728
#define SKEY_PID_LEN        1792

#define SKEY_MAC_STR_LEN    18    /* "AA:BB:CC:DD:EE:FF\0" */
#define SKEY_DEVICE_ID_BUF  23    /* 22 + '\0' */
#define SKEY_UUID_BUF       23
#define SKEY_PUBKEY_PEM_MAX 512
#define SKEY_SIG_B64_MAX    512   /* 256 字节签名 -> 344 字符 Base64 + 余量 */
#define SKEY_PLAINTEXT_MAX  245   /* RSA-2048 PKCS#1 v1.5 最大明文: 256-11 */
#define SKEY_ENC_B64_MAX    512   /* 256 字节密文 -> 344 字符 Base64 + 余量 */
#define SKEY_DEC_BUF_MAX    256   /* 解密输出缓冲区上限 */

#else
/* ---- 静态库模式：使用 libskey 头文件 ---- */
#include <skey.h>	/* SKEY_DEVICE_ID_BUF, SKEY_MAC_STR_LEN, skey_err_t 等 */
#endif /* LOCAL_SKEY */

/* 派生常量（两种模式共用） */
#define SKEY_DEV_ID_LEN		SKEY_DEVICE_ID_BUF	/* device_id 缓冲区大小 */
#define SKEY_MAC_LEN		13			/* 12 hex chars + '\0' */
#define SKEY_PUBKEY_LEN		SKEY_PUBKEY_PEM_MAX	/* RSA-2048 公钥 PEM + '\0' */
#define SKEY_CT_B64_LEN		SKEY_ENC_B64_MAX	/* 加密输出 Base64 缓冲区 */
#define SKEY_PT_BUF_LEN		SKEY_DEC_BUF_MAX	/* 解密输出缓冲区 */

typedef struct {
	char	device_id[SKEY_DEV_ID_LEN];	/* BASE62 编码的 device_id */
	char	mac[SKEY_MAC_LEN];		/* lowercase, no colons, e.g. "e4671e8508ae" */
	char	pubkey[SKEY_PUBKEY_LEN];	/* RSA-2048 公钥 PEM */
} skey_info_t;

/*
 * 初始化 skey 并获取 device_id、MAC 和 RSA 公钥。
 * LOCAL_SKEY 模式：从本地文件读取 device_id 和公钥，MAC 留空（由 device_info.c 从 local_if 获取）。
 * 静态库模式：从 Factory 分区读取，MAC 转换为小写去冒号格式。
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

#endif /* XFRPC_LOADER_SKEY_H */
