/*
 * Copyright 2026 Davide Guerri <davide.guerri@gmail.com>
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

/*
 * Minimal mbedTLS 2.28.x config for loader.c
 *
 * Target: TLS 1.2, ECDHE-ECDSA-AES128-GCM-SHA256
 * Server cert: ECDSA (P-256 or P-384)
 * No old ciphers. No TLS 1.0/1.1.
 */
#ifndef LOADER_MBEDTLS_CONFIG_H
#define LOADER_MBEDTLS_CONFIG_H

/* ---- SSL/TLS ---- */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_PROTO_TLS1_2
/* Disable older protocols */
#undef MBEDTLS_SSL_PROTO_TLS1
#undef MBEDTLS_SSL_PROTO_TLS1_1
#undef MBEDTLS_SSL_PROTO_SSL3

/* ---- Key exchange ---- */
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
/* ECDHE_RSA not needed: server cert is ECDSA. RSA_C is kept only because the
 * Let's Encrypt E7 intermediate is signed by ISRG Root X1 (RSA), so RSA
 * signature verification is required during X.509 chain validation. */
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_RSA_C
#define MBEDTLS_SSL_SERVER_NAME_INDICATION

/* ---- Elliptic curves ---- */
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED /* P-256 — server cert and ECDHE */
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED /* P-384 — may appear in CA chain */

/* ---- Cipher ---- */
#define MBEDTLS_CIPHER_C
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C

/* ---- Hash ---- */
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C /* needed for P-384 cert signatures */

/* ---- X.509 / PEM / ASN.1 ---- */
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_OID_C

/* ---- Bignum (required by ECDSA/X.509) ---- */
#define MBEDTLS_BIGNUM_C

/* ---- Network ---- */
#define MBEDTLS_NET_C

/* ---- RNG ---- */
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C

/* ---- Platform / filesystem ---- */
#define MBEDTLS_PLATFORM_C
// #define MBEDTLS_ERROR_C /* optional: human-readable error strings */
#define MBEDTLS_FS_IO

#include "check_config.h"

#endif /* LOADER_MBEDTLS_CONFIG_H */