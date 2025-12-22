/* psa_chacha20_poly1305.h
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

/**
 * Platform Security Architecture (PSA) ChaCha20-Poly1305 API header
 *
 * If WOLFSSL_PSA_ENGINE is defined, wolfSSL provides an implementation of the
 * PSA Crypto API for ChaCha20-Poly1305 operations that calls wolfCrypt APIs.
 *
 */

#ifndef WOLFSSL_PSA_CHACHA20_POLY1305_H
#define WOLFSSL_PSA_CHACHA20_POLY1305_H

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_PSA_ENGINE) && defined(HAVE_CHACHA) && defined(HAVE_POLY1305)

#include <psa/crypto.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/visibility.h>

/* Check if ChaCha20-Poly1305 algorithm is supported */
WOLFSSL_LOCAL psa_status_t psa_chacha20_poly1305_check_alg_supported(
    psa_algorithm_t alg);

/* Check if ChaCha20-Poly1305 key type is supported */
WOLFSSL_LOCAL psa_status_t psa_chacha20_poly1305_check_key_type_supported(
    psa_key_type_t type);

/* Check if ChaCha20-Poly1305 key size is valid */
WOLFSSL_LOCAL psa_status_t psa_chacha20_poly1305_check_key_size_valid(
    psa_key_type_t type, size_t bits);

/* Encrypt using ChaCha20-Poly1305 */
WOLFSSL_LOCAL psa_status_t psa_chacha20_poly1305_encrypt(
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *plaintext, size_t plaintext_length,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length);

/* Decrypt using ChaCha20-Poly1305 */
WOLFSSL_LOCAL psa_status_t psa_chacha20_poly1305_decrypt(
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length);

#ifdef HAVE_XCHACHA
/* Encrypt using XChaCha20-Poly1305 */
WOLFSSL_LOCAL psa_status_t psa_xchacha20_poly1305_encrypt(
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *plaintext, size_t plaintext_length,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length);

/* Decrypt using XChaCha20-Poly1305 */
WOLFSSL_LOCAL psa_status_t psa_xchacha20_poly1305_decrypt(
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length);
#endif /* HAVE_XCHACHA */

#endif /* WOLFSSL_PSA_ENGINE && HAVE_CHACHA && HAVE_POLY1305 */
#endif /* WOLFSSL_PSA_CHACHA20_POLY1305_H */
