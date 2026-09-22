/* user_settings.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
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

/* The build-config-matrix harness drives every algorithm feature via
 * wolfcrypt-native defines passed on the compiler command line by
 * build-test/build-variant.sh. This file only sets up invariants that are
 * always required (or always forbidden) regardless of the lane. */

#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define WOLFSSL_PSA_ENGINE
#define NO_DSA
/* Constant-time AES, required by src/psa_config.h unless WOLFPSA_AES_FAST is
 * set. Selected here rather than in the BASELINE list so the aes-ecb lane can
 * strip it together with HAVE_AES_ECB, which wolfCrypt requires alongside it. */
#if !defined(WOLFPSA_AES_FAST) && !defined(WOLFPSA_NO_AES_BITSLICED)
#define WC_AES_BITSLICED
#endif
/* psa_sign_hash()/psa_verify_hash() must accept an all-zero digest (PSA
 * treats the hash as opaque bytes); wolfCrypt rejects it by default, so opt
 * out. src/psa_config.h #errors when HAVE_ECC is on and this is undefined. */
#define WC_ALLOW_ECC_ZERO_HASH

#endif /* WOLFSSL_USER_SETTINGS_H */
