/* psa_config.h
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

/* Build-configuration policy shared by every wolfPSA translation unit.
 * Include this instead of <wolfssl/wolfcrypt/settings.h>: it pulls settings.h
 * in first, then applies the checks, so a partial build (one TU compiled on
 * its own) gets the same diagnostics as a full one. */

#ifndef WOLFPSA_CONFIG_H
#define WOLFPSA_CONFIG_H

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_PSA_ENGINE) && !defined(NO_AES)

/* AES backend policy.
 *
 * PSA expects AES to be constant time. wolfCrypt's default software core
 * indexes the T-tables with key- and state-derived bytes, which is a
 * cache-timing channel on a target that has a cache. That core is also the
 * fastest software AES wolfCrypt has, so the choice is the caller's:
 *
 *   default            require a backend with no secret-indexed table load
 *   WOLFPSA_AES_FAST   accept the T-table core; faster, not constant time,
 *                      and not PSA compliant
 *
 * Backends accepted by the default policy:
 *
 *   WC_AES_BITSLICED         portable bitsliced core. Constant time by
 *                            construction, but sizeof(Aes) grows by
 *                            15 * 16 * WC_AES_BS_WORD_SIZE bytes: 123,296
 *                            bytes at the default word size of 64, down to
 *                            2,336 at 8. Pin WC_AES_BS_WORD_SIZE on any
 *                            target where that matters.
 *   WOLFSSL_AES_TOUCH_LINES  every table access touches all cache lines of
 *                            the table, so the access pattern carries no
 *                            secret. sizeof(Aes) is unchanged.
 *   a hardware AES core      the list below is the subset of wolfCrypt's
 *                            backend dispatch (wolfcrypt/src/aes.c) that
 *                            compiles no software tables at all, so there is
 *                            no channel to close. WOLFSSL_AESNI and
 *                            WOLFSSL_ESP32_CRYPT are deliberately absent:
 *                            both keep the T-table core as a runtime
 *                            fallback (AES-NI via AesSetKey_C() when
 *                            Check_CPU_support_AES() says no, ESP32 via
 *                            NEED_AES_HW_FALLBACK for key lengths the
 *                            peripheral does not implement).
 */
#if defined(WOLFSSL_ARMASM) || defined(WOLFSSL_RISCV_ASM) || \
    defined(FREESCALE_LTC) || defined(FREESCALE_MMCAU) || \
    defined(WOLFSSL_SILABS_SE_ACCEL) || defined(WOLFSSL_PSOC6_CRYPTO) || \
    defined(WOLFSSL_AFALG) || defined(WOLFSSL_DEVCRYPTO_AES) || \
    defined(WOLFSSL_PIC32MZ_CRYPT) || defined(WOLFSSL_NRF51_AES) || \
    defined(WOLFSSL_SCE) || defined(HAVE_COLDFIRE_SEC) || \
    defined(WOLF_CRYPTO_CB_ONLY_AES)
    #define WOLFPSA_AES_HW_BACKEND
#endif

#if !defined(WOLFPSA_AES_FAST) && !defined(WC_AES_BITSLICED) && \
    !defined(WOLFSSL_AES_TOUCH_LINES) && !defined(WOLFPSA_AES_HW_BACKEND)
#error "wolfPSA: AES backend is not constant time. Select WC_AES_BITSLICED or WOLFSSL_AES_TOUCH_LINES, or define WOLFPSA_AES_FAST to accept the T-table core."
#endif

/* Both policies cannot hold at once: WOLFPSA_AES_FAST waives the
 * requirement, so selecting a constant-time core alongside it is a
 * contradiction the caller should resolve rather than have silently
 * decided here. */
#if defined(WOLFPSA_AES_FAST) && \
    (defined(WC_AES_BITSLICED) || defined(WOLFSSL_AES_TOUCH_LINES))
#error "wolfPSA: WOLFPSA_AES_FAST conflicts with WC_AES_BITSLICED/WOLFSSL_AES_TOUCH_LINES"
#endif

/* NO_AES is scoped out above because this policy has nothing to say about a
 * build with no AES. wolfPSA itself does not build with NO_AES today
 * (psa_cipher.c and the AEAD/MAC/KDF paths are unguarded), so no matrix lane
 * covers it. */

#endif /* WOLFSSL_PSA_ENGINE && !NO_AES */

/* psa_sign_hash()/psa_verify_hash() must accept an all-zero digest: PSA
 * treats the hash argument as opaque bytes and ECDSA over e = 0 is
 * well-defined. wolfCrypt rejects an all-zero digest by default (a guard
 * against uninitialized buffers), which would surface as
 * PSA_ERROR_INVALID_ARGUMENT for input the spec requires us to accept.
 * WC_ALLOW_ECC_ZERO_HASH opts out of that rejection.
 *
 * The macro is consumed by wolfcrypt/src/ecc.c, not here, so this check only
 * proves the intent of the configuration wolfPSA is compiled with. A build
 * that links a separately configured libwolfssl must set it for that build
 * too; there is no way to observe it from this side. */
#if defined(WOLFSSL_PSA_ENGINE) && defined(HAVE_ECC) \
    && !defined(WC_ALLOW_ECC_ZERO_HASH)
#error "wolfPSA needs WC_ALLOW_ECC_ZERO_HASH (psa_sign_hash/psa_verify_hash must accept an all-zero digest)"
#endif

#endif /* WOLFPSA_CONFIG_H */
