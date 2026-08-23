/* psa_engine.h
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
 * Platform Security Architecture (PSA) Engine header
 *
 * If WOLFSSL_PSA_ENGINE is defined, wolfSSL provides an implementation of the
 * PSA Crypto API that calls wolfCrypt APIs.
 *
 */

#ifndef WOLFSSL_PSA_ENGINE_H
#define WOLFSSL_PSA_ENGINE_H

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_PSA_ENGINE)

#include <psa/crypto.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/visibility.h>

#ifndef NO_AES
#include <wolfssl/wolfcrypt/aes.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* wolfCrypt error code to PSA status code conversion */
WOLFSSL_LOCAL psa_status_t wc_error_to_psa_status(int ret);

/* Default wolfCrypt devId threaded through wolfPSA's internal wc_*Init()
 * calls. Set it to a registered crypto_cb devId (e.g. via
 * wc_CryptoCb_RegisterDevice) to route every wolfPSA-issued wolfCrypt call
 * through that callback, which is the integration hook for crypto offload
 * backends such as wolfHSM or a hardware accelerator. Safe to call before
 * psa_crypto_init().
 *
 * Until this is called wolfPSA expresses no preference and wolfCrypt's own
 * device selection applies (wc_CryptoCb_DefaultDevID(), so
 * WOLFSSL_CAAM_DEVID, WC_USE_DEVID or the first registered device, unless
 * the build sets WC_NO_DEFAULT_DEVID). Any explicit devId wins over that
 * selection, INVALID_DEVID included: passing it forces every wolfPSA
 * operation to run locally even when other devices are registered.
 *
 * Coverage: every algorithm whose wolfCrypt init function accepts a devId,
 * which is AES, 3DES, RSA, ECC, Ed25519, Ed448, X25519, ML-DSA,
 * ML-KEM, LMS, XMSS, SHA-1, the SHA-2 and SHA-3 families, SHAKE, HMAC,
 * CMAC, HKDF, PBKDF2 and the RNG. X448, RIPEMD-160, MD5, Ascon and
 * ChaCha20-Poly1305 always run locally, either because wolfCrypt exposes no
 * devId for them or because it accepts one and ignores it. AES key wrap
 * (PSA_ALG_KW) also stays local for now: wc_AesKeyWrap_ex() falls back to
 * software when the device has no keywrap handler, and a device that
 * installed the KEK through WOLF_CRYPTO_CB_AES_SETKEY leaves no software
 * key schedule for that fallback to use, so the wrap would silently run
 * under all-zero round keys. It joins the list once wolfCrypt refuses that
 * fallback.
 *
 * A callback that does not implement a given algorithm returns
 * CRYPTOCB_UNAVAILABLE and wolfCrypt falls back to software. One case needs
 * more than that: a backend that keeps per-operation state in devCtx should
 * be built with WOLF_CRYPTO_CB_COPY and WOLF_CRYPTO_CB_FREE, otherwise
 * psa_hash_clone() duplicates the handle and psa_hash_abort() never
 * releases it.
 *
 * Threading: the default devId is held in a process-global variable read
 * by every wolfPSA-internal wc_*Init() invocation. Callers must set it
 * during single-threaded initialisation (before any PSA operation is
 * issued) or otherwise serialise the setter with external synchronisation;
 * concurrent calls to wolfPSA_SetDefaultDevID() while PSA operations are
 * in flight are not supported.
 *
 * Returns 0 on success. */
WOLFSSL_API int wolfPSA_SetDefaultDevID(int devId);

/* Returns the devId wolfPSA passes to wolfCrypt: the value given to
 * wolfPSA_SetDefaultDevID(), or wolfCrypt's own selection when that was
 * never called. It is therefore not a test for whether a devId was
 * configured, and it can name a device nobody asked wolfPSA to use. */
WOLFSSL_API int wolfPSA_GetDefaultDevID(void);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_PSA_ENGINE */
#endif /* WOLFSSL_PSA_ENGINE_H */
