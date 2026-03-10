/* user_settings.h
 *
 * Copyright (C) 2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define WOLFSSL_PSA_ENGINE
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_1024
#define WOLFSSL_SP_384
#define HAVE_SP_ECC
#define RSA_MIN_SIZE 1024
#define WOLFSSL_KEY_GEN
#define WC_NO_HARDEN
#define WOLFSSL_HAVE_PRF
#define HAVE_HKDF
#define HAVE_PBKDF2
#define WOLFSSL_MD5
#define WOLFSSL_RIPEMD
#define WOLFSSL_SHA224
#define WOLFSSL_SHA256
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#undef NO_MD5
#undef NO_DES3
#define HAVE_ECC
#define HAVE_ECC384
#define HAVE_ECC_KEY_EXPORT
#define HAVE_ECC_KEY_IMPORT
#define WOLFSSL_ECDSA_DETERMINISTIC_K
#define WC_RSA_PSS
#define WOLFSSL_PSS_SALT_LEN_DISCOVER
#define WOLFSSL_RSA_OAEP
#define WOLFSSL_DES3
#define WOLFSSL_DES_ECB
#define HAVE_AESGCM
#define HAVE_AESCCM
#define HAVE_AES_ECB
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_CFB
#define WOLFSSL_AES_OFB
#define WOLFSSL_CMAC
#define HAVE_CHACHA
#define HAVE_POLY1305

#endif /* WOLFSSL_USER_SETTINGS_H */
