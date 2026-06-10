/* crypto_config.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfPSA.
 *
 * wolfPSA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfPSA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef WOLFPSA_CRYPTO_CONFIG_H
#define WOLFPSA_CRYPTO_CONFIG_H


#define PSA_WANT_ALG_SHA_1
#define PSA_WANT_ALG_SHA_224
#define PSA_WANT_ALG_SHA_256
#define PSA_WANT_ALG_SHA_384
#define PSA_WANT_ALG_SHA_512

#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC
#define PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY

#define PSA_WANT_KEY_TYPE_ML_DSA
#define PSA_WANT_KEY_TYPE_ML_KEM

#endif
