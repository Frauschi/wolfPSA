/* psa_opaque_driver_els_pkc.c
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
 * The NXP EdgeLock (ELS) key store as a wolfPSA opaque driver.
 *
 * What wolfPSA stores for such a key is the crypto callback port's id blob,
 * followed for a generated key by its public point - the hardware will not
 * hand a slot key's public part back later, so it is kept now or not at all.
 *
 * ELS has no plaintext path in either direction, so psa_import_key() here
 * means "adopt this slot", never "load this material". A symmetric key arrives
 * through psa_unwrap_key() or a derivation, and leaves only wrapped.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_PSA_ENGINE)

#include "psa_opaque_driver_els_pkc.h"

#ifdef WOLFPSA_HAVE_ELS_KEYSTORE

#include <wolfpsa/psa_engine.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_keystore.h>
#include <wolfssl/wolfcrypt/port/nxp/els_pkc_port.h>

/* The reference, then the X9.62 point. The key store holds P-256 and nothing
 * else, so this is the only size a generated key ever needs. */
#define ELS_PKC_PUB_SZ      (1 + (2 * 32))
#define ELS_PKC_KEY_DATA_SZ (WC_ELSPKC_KEYREF_SZ + ELS_PKC_PUB_SZ)

/* Which ELS permission a PSA key is asking for. Every class maps 1:1 onto one
 * permission bit, so this is also the check that the key is one ELS can hold:
 * WC_ELSPKC_KEY_NONE means no. */
static byte els_pkc_key_class(const psa_key_attributes_t* attributes)
{
    psa_key_type_t type = psa_get_key_type(attributes);
    psa_algorithm_t alg = psa_get_key_algorithm(attributes);

#ifdef HAVE_ECC
    if (type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1) &&
        psa_get_key_bits(attributes) == 256) {
        if (PSA_ALG_IS_ECDH(alg) || PSA_ALG_IS_KEY_AGREEMENT(alg)) {
            return WC_ELSPKC_KEY_ECC_DH;
        }
        return WC_ELSPKC_KEY_ECC_SIGN;
    }
#endif

    if (type == PSA_KEY_TYPE_AES) {
        size_t bits = psa_get_key_bits(attributes);

        /* ELS keys are 128 or 256 bits; a 192-bit slot does not exist. */
        if (bits != 128 && bits != 256) {
            return WC_ELSPKC_KEY_NONE;
        }
        if (PSA_ALG_IS_KEY_WRAP(alg)) {
            return WC_ELSPKC_KEY_KWK;
        }
        if (alg == PSA_ALG_CMAC || alg == PSA_ALG_SP800_108_COUNTER_CMAC) {
            return WC_ELSPKC_KEY_CMAC;
        }
        return WC_ELSPKC_KEY_AES;
    }

    if (type == PSA_KEY_TYPE_HMAC) {
        return WC_ELSPKC_KEY_HMAC;
    }

    /* A generic derivation key is the parent of a slot-to-slot derivation,
     * which on this hardware is CKDF. */
    if (type == PSA_KEY_TYPE_DERIVE) {
        return WC_ELSPKC_KEY_CKDF;
    }

    return WC_ELSPKC_KEY_NONE;
}

/* The wc_KeyStore_* key type for a class, so an op can hand the port a type to
 * cross-check the target reference against. */
static word32 els_pkc_key_store_type(byte keyClass)
{
    switch (keyClass) {
        case WC_ELSPKC_KEY_ECC_SIGN: return WC_KEYSTORE_KEY_ECC_SIGN;
        case WC_ELSPKC_KEY_ECC_DH:   return WC_KEYSTORE_KEY_ECC_DH;
        case WC_ELSPKC_KEY_ECC_SEED: return WC_KEYSTORE_KEY_DERIVE;
        case WC_ELSPKC_KEY_AES:      return WC_KEYSTORE_KEY_AES;
        case WC_ELSPKC_KEY_HMAC:     return WC_KEYSTORE_KEY_HMAC;
        case WC_ELSPKC_KEY_CMAC:     return WC_KEYSTORE_KEY_CMAC;
        case WC_ELSPKC_KEY_KWK:      return WC_KEYSTORE_KEY_WRAP;
        case WC_ELSPKC_KEY_CKDF:     return WC_KEYSTORE_KEY_DERIVE;
        case WC_ELSPKC_KEY_HKDF:     return WC_KEYSTORE_KEY_DERIVE;
        default:                     return WC_KEYSTORE_KEY_NONE;
    }
}

/* The key's size in bytes, which is what decides whether it needs a slot pair.
 * Zero when the attributes carry no size, leaving the choice to the port. */
static word32 els_pkc_key_bytes(const psa_key_attributes_t* attributes)
{
    return (word32)PSA_BITS_TO_BYTES(psa_get_key_bits(attributes));
}

/* Reserve a slot for a key the caller is about to create and serialise its
 * reference. Nothing is marked taken until a key is written, so a failure
 * afterwards leaves no slot to release. */
static psa_status_t els_pkc_reserve(const psa_key_attributes_t* attributes,
                                    wc_ElsPkc_KeyRef* ref, uint8_t* key_data,
                                    size_t key_data_size)
{
    word32 refSz = WC_ELSPKC_KEYREF_SZ;
    byte keyClass = els_pkc_key_class(attributes);
    int ret;

    if (keyClass == WC_ELSPKC_KEY_NONE) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (key_data_size < WC_ELSPKC_KEYREF_SZ) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    ret = wc_ElsPkc_ReserveSlot(keyClass, els_pkc_key_bytes(attributes), ref);
    if (ret != 0) {
        return (ret == MEMORY_E) ? PSA_ERROR_INSUFFICIENT_STORAGE
                                 : PSA_ERROR_HARDWARE_FAILURE;
    }

    ret = wc_ElsPkc_MakeKeyRef(ref, key_data, &refSz);
    /* Anything a key stores after the reference sits at a fixed offset, so a
     * shorter reference would be read back as a longer one. */
    if (ret == 0 && refSz != WC_ELSPKC_KEYREF_SZ) {
        ret = BUFFER_E;
    }

    return (ret == 0) ? PSA_SUCCESS : PSA_ERROR_HARDWARE_FAILURE;
}

static psa_status_t els_pkc_validate(const psa_key_attributes_t* attributes,
                                     const uint8_t* data, size_t data_length)
{
    wc_ElsPkc_KeyRef ref;

    /* A reserved slot does not survive a reset, so there is nothing a
     * persistent record could still name after one. ELS can mark a key
     * exportable and a wrapped copy would outlive the reset, but wolfPSA does
     * not keep one yet. */
    if (!PSA_KEY_LIFETIME_IS_VOLATILE(psa_get_key_lifetime(attributes))) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (els_pkc_key_class(attributes) == WC_ELSPKC_KEY_NONE) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    /* Reject a malformed reference here rather than let it travel as far as
     * the public-key export, which would do arithmetic on a short blob. */
    if (data != NULL &&
        (data_length < WC_ELSPKC_KEYREF_SZ ||
         wc_ElsPkc_ParseKeyRef(data, (word32)data_length, &ref) != 0)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

static psa_status_t els_pkc_generate(const psa_key_attributes_t* attributes,
                                     uint8_t* key_data, size_t key_data_size,
                                     size_t* key_data_length)
{
#ifdef HAVE_ECC
    wc_ElsPkc_KeyRef ref;
    ecc_key ecc;
    WC_RNG rng;
    word32 pubSz = ELS_PKC_PUB_SZ;
    psa_status_t status;
    int ret;

    /* ELS generates ECC key pairs and nothing else: a symmetric slot key is
     * unwrapped in or derived, never generated in place. */
    if (!PSA_KEY_TYPE_IS_ECC_KEY_PAIR(psa_get_key_type(attributes))) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (key_data_size < ELS_PKC_KEY_DATA_SZ) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* PSA's generate takes no input, so the slot is chosen here. */
    status = els_pkc_reserve(attributes, &ref, key_data, key_data_size);
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* The port's key generation never reads this, but wc_ecc_make_key_ex()
     * rejects a NULL rng before the callback is ever reached. */
    ret = wc_InitRng_ex(&rng, NULL, wolfPSA_GetDefaultDevID());
    if (ret != 0) {
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    /* On failure EccUseSlot has either not initialised the key or freed it
     * already; only the success path owns an initialised object. */
    ret = wc_ElsPkc_EccUseSlot(&ecc, &ref, NULL, WOLFSSL_ELS_PKC_DEVID);
    if (ret != 0) {
        wc_FreeRng(&rng);
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    ret = wc_ecc_make_key_ex(&rng, 32, &ecc, ECC_SECP256R1);
    if (ret == 0) {
        ret = wc_ecc_export_x963_ex(&ecc, key_data + WC_ELSPKC_KEYREF_SZ,
                                    &pubSz, 0);
    }
    wc_FreeRng(&rng);
    wc_ecc_free(&ecc);

    if (ret != 0) {
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    *key_data_length = WC_ELSPKC_KEYREF_SZ + (size_t)pubSz;
    return PSA_SUCCESS;
#else
    (void)attributes;
    (void)key_data;
    (void)key_data_size;
    (void)key_data_length;
    return PSA_ERROR_NOT_SUPPORTED;
#endif
}

static psa_status_t els_pkc_destroy(const psa_key_attributes_t* attributes,
                                    const uint8_t* key_data,
                                    size_t key_data_length)
{
    (void)attributes;

    if (wc_KeyStore_Delete(WOLFSSL_ELS_PKC_DEVID, key_data,
                           (word32)key_data_length, NULL) != 0) {
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    return PSA_SUCCESS;
}

static psa_status_t els_pkc_export_public(
    const psa_key_attributes_t* attributes, const uint8_t* key_data,
    size_t key_data_length, uint8_t* data, size_t data_size,
    size_t* data_length)
{
    size_t point_len;

    (void)attributes;

    /* A key imported as a bare reference carries no point to return. */
    if (key_data_length <= WC_ELSPKC_KEYREF_SZ) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    point_len = key_data_length - WC_ELSPKC_KEYREF_SZ;
    if (data_size < point_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    XMEMCPY(data, key_data + WC_ELSPKC_KEYREF_SZ, point_len);
    *data_length = point_len;
    return PSA_SUCCESS;
}

static psa_status_t els_pkc_wrap(const psa_key_attributes_t* wrap_attributes,
                                 const uint8_t* wrap_key_data,
                                 size_t wrap_key_data_length,
                                 psa_algorithm_t alg,
                                 const psa_key_attributes_t* attributes,
                                 const uint8_t* key_data,
                                 size_t key_data_length,
                                 uint8_t* data, size_t data_size,
                                 size_t* data_length)
{
    word32 blobSz = (word32)data_size;
    int ret;

    (void)attributes;

    /* The container carries the key's property word, which a bare RFC 3394
     * blob has nowhere to put, so PSA_ALG_KW cannot describe it. */
    if (alg != PSA_ALG_KW) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (els_pkc_key_class(wrap_attributes) != WC_ELSPKC_KEY_KWK) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    ret = wc_KeyStore_ExportWrapped(WOLFSSL_ELS_PKC_DEVID, key_data,
                                    (word32)key_data_length, wrap_key_data,
                                    (word32)wrap_key_data_length,
                                    WC_KEYWRAP_FORMAT_VENDOR, data, &blobSz,
                                    NULL);
    if (ret == LENGTH_ONLY_E || ret == BUFFER_E) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    *data_length = (size_t)blobSz;
    return PSA_SUCCESS;
}

static psa_status_t els_pkc_unwrap(const psa_key_attributes_t* wrap_attributes,
                                   const uint8_t* wrap_key_data,
                                   size_t wrap_key_data_length,
                                   psa_algorithm_t alg,
                                   const psa_key_attributes_t* attributes,
                                   const uint8_t* data, size_t data_length,
                                   uint8_t* key_data, size_t key_data_size,
                                   size_t* key_data_length)
{
    wc_ElsPkc_KeyRef ref;
    psa_status_t status;
    int ret;

    if (alg != PSA_ALG_KW) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (els_pkc_key_class(wrap_attributes) != WC_ELSPKC_KEY_KWK) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = els_pkc_reserve(attributes, &ref, key_data, key_data_size);
    if (status != PSA_SUCCESS) {
        return status;
    }

    ret = wc_KeyStore_ImportWrapped(WOLFSSL_ELS_PKC_DEVID, key_data,
                                    WC_ELSPKC_KEYREF_SZ,
                                    els_pkc_key_store_type(ref.keyClass),
                                    wrap_key_data,
                                    (word32)wrap_key_data_length,
                                    WC_KEYWRAP_FORMAT_VENDOR, data,
                                    (word32)data_length, 0, NULL);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    /* No public point: an unwrapped key is whatever the container held, and
     * ELS will not compute a public part for it afterwards. */
    *key_data_length = WC_ELSPKC_KEYREF_SZ;
    return PSA_SUCCESS;
}

static psa_status_t els_pkc_derive(const psa_key_attributes_t* attributes,
                                   const psa_key_attributes_t* src_attributes,
                                   const uint8_t* src_key_data,
                                   size_t src_key_data_length,
                                   psa_algorithm_t alg, const uint8_t* input,
                                   size_t input_length, uint8_t* key_data,
                                   size_t key_data_size,
                                   size_t* key_data_length)
{
    wc_ElsPkc_KeyRef ref;
    psa_status_t status;
    int ret;

    /* CKDF is NIST SP800-108 counter mode over CMAC, so that is the only PSA
     * algorithm this hardware can be asked for. */
    if (alg != PSA_ALG_SP800_108_COUNTER_CMAC) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (els_pkc_key_class(src_attributes) != WC_ELSPKC_KEY_CKDF) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = els_pkc_reserve(attributes, &ref, key_data, key_data_size);
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* The port fixes the derivation-data length, so a caller whose context
     * step was a different size is told this device cannot serve it. */
    ret = wc_KeyStore_Derive(WOLFSSL_ELS_PKC_DEVID, key_data,
                             WC_ELSPKC_KEYREF_SZ,
                             els_pkc_key_store_type(ref.keyClass),
                             els_pkc_key_bytes(attributes),
                             src_key_data, (word32)src_key_data_length,
                             0, input, (word32)input_length, 0, NULL);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    *key_data_length = WC_ELSPKC_KEYREF_SZ;
    return PSA_SUCCESS;
}

#ifdef HAVE_ECC
static psa_status_t els_pkc_ecc_bind(const uint8_t* key_data,
                                     size_t key_data_length, int curve_id,
                                     psa_algorithm_t alg, ecc_key* key)
{
    wc_ElsPkc_KeyRef ref;
    int ret;

    /* RFC 6979 derives its nonce from the scalar the vault exists to keep
     * inside, so a deterministic signature is impossible for such a key. */
    if (PSA_ALG_IS_DETERMINISTIC_ECDSA(alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    /* The key store holds P-256 and nothing else; another curve would
     * otherwise get a P-256 signature laid out for the width it asked. */
    if (curve_id != ECC_SECP256R1) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (wc_ElsPkc_ParseKeyRef(key_data, (word32)key_data_length, &ref) != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    ret = wc_ElsPkc_EccUseSlot(key, &ref, NULL, WOLFSSL_ELS_PKC_DEVID);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    return PSA_SUCCESS;
}
#endif /* HAVE_ECC */

#ifndef NO_AES
static psa_status_t els_pkc_aes_bind(const uint8_t* key_data,
                                     size_t key_data_length,
                                     psa_algorithm_t alg, Aes* aes)
{
    wc_ElsPkc_KeyRef ref;
    psa_algorithm_t base = PSA_ALG_IS_AEAD(alg) ?
                           PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(alg) : alg;
    int ret;

    /* The four modes the port's cipher callback claims. Anything else would
     * fall back to software, which has no key to work with. */
    if (base != PSA_ALG_GCM && base != PSA_ALG_CBC_NO_PADDING &&
        base != PSA_ALG_CBC_PKCS7 && base != PSA_ALG_CTR &&
        base != PSA_ALG_ECB_NO_PADDING) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (wc_ElsPkc_ParseKeyRef(key_data, (word32)key_data_length, &ref) != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (ref.keyClass != WC_ELSPKC_KEY_AES) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    ret = wc_ElsPkc_AesUseSlot(aes, &ref, NULL, WOLFSSL_ELS_PKC_DEVID);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    return PSA_SUCCESS;
}
#endif /* NO_AES */

#if defined(WOLFSSL_CMAC) && !defined(NO_AES)
static psa_status_t els_pkc_cmac_bind(const uint8_t* key_data,
                                      size_t key_data_length,
                                      psa_algorithm_t alg, Cmac* cmac)
{
    wc_ElsPkc_KeyRef ref;
    int ret;

    if (alg != PSA_ALG_CMAC) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (wc_ElsPkc_ParseKeyRef(key_data, (word32)key_data_length, &ref) != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    /* ucmac is a separate permission from uaes, so a cipher slot cannot serve
     * a MAC even though both hold an AES key. */
    if (ref.keyClass != WC_ELSPKC_KEY_CMAC) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    ret = wc_ElsPkc_CmacUseSlot(cmac, &ref, NULL, WOLFSSL_ELS_PKC_DEVID);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    return PSA_SUCCESS;
}
#endif /* WOLFSSL_CMAC && !NO_AES */

/* export_private, copy and key_agreement stay NULL: ELS releases no plaintext
 * key, cannot duplicate a slot key independently of its original, and keeps
 * an ECDH shared secret inside for a derivation it runs itself. */
const wolfpsa_opaque_driver wolfpsa_opaque_driver_els_pkc = {
    PSA_KEY_LOCATION_ELS_PKC,
    PSA_KEY_LOCATION_EXTERNAL_STORAGE,
    ELS_PKC_KEY_DATA_SZ,
    els_pkc_validate,
    els_pkc_generate,
    els_pkc_destroy,
    els_pkc_export_public,
    NULL,                       /* export_private */
    NULL,                       /* copy */
    NULL,                       /* key_agreement */
    els_pkc_wrap,
    els_pkc_unwrap,
    els_pkc_derive
#ifdef HAVE_ECC
    , els_pkc_ecc_bind
#endif
#ifndef NO_AES
    , els_pkc_aes_bind
#endif
#if defined(WOLFSSL_CMAC) && !defined(NO_AES)
    , els_pkc_cmac_bind
#endif
};

#endif /* WOLFPSA_HAVE_ELS_KEYSTORE */

#endif /* WOLFSSL_PSA_ENGINE */
