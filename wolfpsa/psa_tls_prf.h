/* psa_tls_prf.h
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

/**
 * Platform Security Architecture (PSA) TLS PRF API header
 *
 * If WOLFSSL_PSA_ENGINE is defined, wolfSSL provides an implementation of the
 * PSA Crypto API for TLS PRF operations that calls wolfCrypt APIs.
 *
 */

#ifndef WOLFSSL_PSA_TLS_PRF_H
#define WOLFSSL_PSA_TLS_PRF_H

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_PSA_ENGINE) && defined(WOLFSSL_TLS13)

#include <psa/crypto.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/visibility.h>

/* Check if TLS PRF algorithm is supported */
WOLFSSL_LOCAL psa_status_t psa_tls_prf_check_alg_supported(psa_algorithm_t alg);

/* TLS 1.3 PRF (HKDF) */
WOLFSSL_LOCAL psa_status_t psa_tls13_prf(
    psa_algorithm_t alg,
    const uint8_t *secret, size_t secret_length,
    const uint8_t *label, size_t label_length,
    const uint8_t *context, size_t context_length,
    uint8_t *output, size_t output_length);

/* TLS 1.3 HKDF Extract */
WOLFSSL_LOCAL psa_status_t psa_tls13_hkdf_extract(
    psa_algorithm_t alg,
    const uint8_t *salt, size_t salt_length,
    const uint8_t *ikm, size_t ikm_length,
    uint8_t *output, size_t output_size, size_t *output_length);

/* TLS 1.3 HKDF Expand */
WOLFSSL_LOCAL psa_status_t psa_tls13_hkdf_expand(
    psa_algorithm_t alg,
    const uint8_t *prk, size_t prk_length,
    const uint8_t *info, size_t info_length,
    uint8_t *output, size_t output_length);

/* TLS 1.3 HKDF Expand Label */
WOLFSSL_LOCAL psa_status_t psa_tls13_hkdf_expand_label(
    psa_algorithm_t alg,
    const uint8_t *secret, size_t secret_length,
    const uint8_t *label, size_t label_length,
    const uint8_t *context, size_t context_length,
    uint8_t *output, size_t output_length);

#endif /* WOLFSSL_PSA_ENGINE && WOLFSSL_TLS13 */
#endif /* WOLFSSL_PSA_TLS_PRF_H */
