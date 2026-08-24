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

#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Pass this to wolfPSA_SetDefaultDevID() to hand the choice back to
 * wolfCrypt, which is where wolfPSA starts before anything configures it.
 * It is deliberately not a devId any device can register under, and it is
 * distinct from INVALID_DEVID because that value means something else
 * here: forcing local execution. */
#define WOLFPSA_DEVID_DEFAULT INT_MIN

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
 * WOLFPSA_DEVID_DEFAULT goes back to letting wolfCrypt choose, so no
 * setting is a one-way door.
 *
 * Coverage: every algorithm whose wolfCrypt init function accepts a devId,
 * which is AES, 3DES, AES-KW, RSA, ECC, Ed25519, Ed448, X25519, X448,
 * ML-DSA, ML-KEM, LMS, XMSS, SHA-1, the SHA-2 and SHA-3 families, SHAKE,
 * HMAC, CMAC, HKDF, PBKDF2 and the RNG, subject to the X25519 caveat
 * below. RIPEMD-160, MD5, Ascon and ChaCha20-Poly1305 always run locally,
 * either because wolfCrypt exposes no devId for them or because it accepts
 * one and ignores it.
 *
 * A callback that does not implement a given algorithm returns
 * CRYPTOCB_UNAVAILABLE and wolfCrypt falls back to software. One case needs
 * more than that: a backend that keeps per-operation state in devCtx should
 * be built with WOLF_CRYPTO_CB_COPY and WOLF_CRYPTO_CB_FREE, otherwise
 * psa_hash_clone() duplicates the handle and psa_hash_abort() never
 * releases it.
 *
 * Two exceptions to the paragraphs above, both outside wolfPSA's control:
 *
 * Deriving an X25519 public key from its private scalar reaches whichever
 * device is registered first, whatever this devId says, including the
 * INVALID_DEVID opt-out. wolfCrypt derives it through
 * wc_curve25519_make_pub(), which takes raw buffers rather than a key and
 * carries no devId (wc_CryptoCb_Curve25519MakePub() falls back to the
 * device at index 0); wc_curve25519_export_public_ex() routes there too, so
 * there is no key-bound path to use instead. Curve448 took a devId in the
 * equivalent call and is unaffected, as are X25519 key generation and key
 * agreement.
 *
 * A build that defines WOLF_CRYPTO_CB_FIND makes wolfCrypt consult its find
 * callback for every operation regardless of devId, so INVALID_DEVID stops
 * meaning local execution there.
 *
 * Threading: the value is held in one atomic process-global, so calling
 * this while other threads issue PSA operations is defined behaviour. It
 * is not a barrier, and the granularity is finer than it looks: the value
 * is read once per wolfCrypt object, not once per PSA operation. A single
 * ECDSA signature reads it twice, for the key and for the RNG, and an X448
 * agreement three times, so an operation running across the change can
 * take one devId for part of its work and another for the rest. Callers
 * that need a definite point of switch have to quiesce their own PSA
 * traffic around the call.
 *
 * Restoring a previous setting: use WOLFPSA_DEVID_DEFAULT, never a value
 * read back from wolfPSA_GetDefaultDevID(). The getter resolves the
 * deferred state rather than reporting it, so saving and restoring its
 * result turns "let wolfCrypt choose" into a hard pin on whatever device
 * happened to be selected, or into forced local execution if none was.
 *
 * Returns 0 on success, or NOT_COMPILED_IN when a real devId is given to a
 * library built without WOLF_CRYPTO_CB, where no dispatch exists to honour
 * it. INVALID_DEVID and WOLFPSA_DEVID_DEFAULT are accepted by every build,
 * because neither asks for an offload.
 *
 * These two functions speak wolfCrypt, not PSA: they take and return the
 * int devId and the wolfCrypt error codes from error-crypt.h, unlike every
 * psa_* entry point, which returns psa_status_t. Do not feed the result to
 * a PSA status mapper. */
WOLFSSL_API int wolfPSA_SetDefaultDevID(int devId);

/* Returns the devId wolfPSA passes to wolfCrypt: the value given to
 * wolfPSA_SetDefaultDevID(), or wolfCrypt's own selection while the
 * setting is WOLFPSA_DEVID_DEFAULT. It is therefore not a test for whether
 * a devId was configured, and it can name a device nobody asked wolfPSA to
 * use. It never returns WOLFPSA_DEVID_DEFAULT itself. */
WOLFSSL_API int wolfPSA_GetDefaultDevID(void);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_PSA_ENGINE */
#endif /* WOLFSSL_PSA_ENGINE_H */
