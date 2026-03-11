/* psa_key_derivation.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_PSA_ENGINE)

#include <psa/crypto.h>
#include <wolfpsa/psa_engine.h>
#include <wolfpsa/psa_key_storage.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/mem_track.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/misc.h>
#ifndef NO_INLINE
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

typedef struct wolfpsa_kdf_ctx {
    psa_algorithm_t alg;
    psa_algorithm_t ka_alg;
    size_t capacity;
    uint32_t steps_set;
    uint8_t *secret;
    size_t secret_length;
    uint8_t *other_secret;
    size_t other_secret_length;
    uint8_t *salt;
    size_t salt_length;
    uint8_t *info;
    size_t info_length;
    uint8_t *label;
    size_t label_length;
    uint8_t *seed;
    size_t seed_length;
    uint8_t *password;
    size_t password_length;
    uint32_t cost;
    int is_key_agreement;
    int is_raw_kdf;
    int output_started;
} wolfpsa_kdf_ctx_t;

#define WOLFPSA_KDF_STEP_SECRET        (1u << 0)
#define WOLFPSA_KDF_STEP_OTHER_SECRET  (1u << 1)
#define WOLFPSA_KDF_STEP_SALT          (1u << 2)
#define WOLFPSA_KDF_STEP_INFO          (1u << 3)
#define WOLFPSA_KDF_STEP_LABEL         (1u << 4)
#define WOLFPSA_KDF_STEP_SEED          (1u << 5)
#define WOLFPSA_KDF_STEP_PASSWORD      (1u << 6)
#define WOLFPSA_KDF_STEP_COST          (1u << 7)

static wolfpsa_kdf_ctx_t* wolfpsa_kdf_get_ctx(psa_key_derivation_operation_t *operation)
{
    if (operation == NULL) {
        return NULL;
    }
    return (wolfpsa_kdf_ctx_t *)(uintptr_t)operation->opaque;
}

static void wolfpsa_kdf_free_buf(uint8_t **buf, size_t *len)
{
    if (buf != NULL && *buf != NULL) {
        wc_ForceZero(*buf, len != NULL ? *len : 0);
        XFREE(*buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        *buf = NULL;
    }
    if (len != NULL) {
        *len = 0;
    }
}

static psa_status_t wolfpsa_kdf_append(uint8_t **buf, size_t *len,
                                       const uint8_t *data, size_t data_length)
{
    uint8_t *new_buf;

    if (data == NULL && data_length > 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (data_length == 0) {
        return PSA_SUCCESS;
    }
    if (*len > SIZE_MAX - data_length) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    new_buf = (uint8_t *)XMALLOC(*len + data_length, NULL,
                                 DYNAMIC_TYPE_TMP_BUFFER);
    if (new_buf == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    if (*buf != NULL) {
        XMEMCPY(new_buf, *buf, *len);
        wc_ForceZero(*buf, *len);
        XFREE(*buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    XMEMCPY(new_buf + *len, data, data_length);
    *buf = new_buf;
    *len += data_length;

    return PSA_SUCCESS;
}

static int wolfpsa_hash_type_from_alg(psa_algorithm_t alg)
{
    psa_algorithm_t hash_alg = 0;

    if (PSA_ALG_IS_ANY_HKDF(alg)) {
        hash_alg = PSA_ALG_HKDF_GET_HASH(alg);
    }
    else if (PSA_ALG_IS_TLS12_PRF(alg)) {
        hash_alg = PSA_ALG_TLS12_PRF_GET_HASH(alg);
    }
    else if (PSA_ALG_IS_TLS12_PSK_TO_MS(alg)) {
        hash_alg = PSA_ALG_TLS12_PSK_TO_MS_GET_HASH(alg);
    }
    else if (PSA_ALG_IS_PBKDF2_HMAC(alg)) {
        hash_alg = PSA_ALG_PBKDF2_HMAC_GET_HASH(alg);
    }

    switch (hash_alg) {
        case PSA_ALG_SHA_1:
            return WC_HASH_TYPE_SHA;
        case PSA_ALG_SHA_224:
            return WC_HASH_TYPE_SHA224;
        case PSA_ALG_SHA_256:
            return WC_HASH_TYPE_SHA256;
        case PSA_ALG_SHA_384:
            return WC_HASH_TYPE_SHA384;
        case PSA_ALG_SHA_512:
            return WC_HASH_TYPE_SHA512;
        case PSA_ALG_SHA_512_224:
            return WC_HASH_TYPE_SHA512_224;
        case PSA_ALG_SHA_512_256:
            return WC_HASH_TYPE_SHA512_256;
        default:
            return WC_HASH_TYPE_NONE;
    }
}

static psa_status_t wolfpsa_kdf_require_output(wolfpsa_kdf_ctx_t *ctx,
                                               size_t output_length)
{
    if (ctx->capacity == PSA_KEY_DERIVATION_UNLIMITED_CAPACITY) {
        return PSA_SUCCESS;
    }
    if (ctx->capacity < output_length) {
        ctx->capacity = 0;
        return PSA_ERROR_INSUFFICIENT_DATA;
    }
    ctx->capacity -= output_length;
    return PSA_SUCCESS;
}

static uint32_t wolfpsa_kdf_step_mask(psa_key_derivation_step_t step)
{
    switch (step) {
        case PSA_KEY_DERIVATION_INPUT_SECRET:
            return WOLFPSA_KDF_STEP_SECRET;
        case PSA_KEY_DERIVATION_INPUT_OTHER_SECRET:
            return WOLFPSA_KDF_STEP_OTHER_SECRET;
        case PSA_KEY_DERIVATION_INPUT_SALT:
            return WOLFPSA_KDF_STEP_SALT;
        case PSA_KEY_DERIVATION_INPUT_INFO:
            return WOLFPSA_KDF_STEP_INFO;
        case PSA_KEY_DERIVATION_INPUT_LABEL:
            return WOLFPSA_KDF_STEP_LABEL;
        case PSA_KEY_DERIVATION_INPUT_SEED:
            return WOLFPSA_KDF_STEP_SEED;
        case PSA_KEY_DERIVATION_INPUT_PASSWORD:
            return WOLFPSA_KDF_STEP_PASSWORD;
        case PSA_KEY_DERIVATION_INPUT_COST:
            return WOLFPSA_KDF_STEP_COST;
        default:
            return 0;
    }
}

static psa_status_t wolfpsa_kdf_validate_step(wolfpsa_kdf_ctx_t *ctx,
                                              psa_key_derivation_step_t step,
                                              size_t data_length)
{
    int hash_len;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->output_started) {
        return PSA_ERROR_BAD_STATE;
    }
    if (step == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->is_raw_kdf) {
        if (step != PSA_KEY_DERIVATION_INPUT_SECRET) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        return PSA_SUCCESS;
    }

    if (PSA_ALG_IS_ANY_HKDF(ctx->alg)) {
        if (step == PSA_KEY_DERIVATION_INPUT_OTHER_SECRET ||
            step == PSA_KEY_DERIVATION_INPUT_LABEL ||
            step == PSA_KEY_DERIVATION_INPUT_SEED ||
            step == PSA_KEY_DERIVATION_INPUT_PASSWORD ||
            step == PSA_KEY_DERIVATION_INPUT_COST) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        if (PSA_ALG_IS_HKDF_EXTRACT(ctx->alg)) {
            if (step == PSA_KEY_DERIVATION_INPUT_INFO) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            if (step == PSA_KEY_DERIVATION_INPUT_SALT) {
                if (ctx->steps_set != 0) {
                    return PSA_ERROR_BAD_STATE;
                }
                return PSA_SUCCESS;
            }
            if (step == PSA_KEY_DERIVATION_INPUT_SECRET) {
                if ((ctx->steps_set & WOLFPSA_KDF_STEP_SALT) == 0) {
                    return PSA_ERROR_BAD_STATE;
                }
                if ((ctx->steps_set & WOLFPSA_KDF_STEP_SECRET) != 0) {
                    return PSA_ERROR_BAD_STATE;
                }
                return PSA_SUCCESS;
            }
        }

        if (PSA_ALG_IS_HKDF_EXPAND(ctx->alg)) {
            if (step == PSA_KEY_DERIVATION_INPUT_SALT) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            if (step == PSA_KEY_DERIVATION_INPUT_SECRET) {
                if (ctx->steps_set != 0) {
                    return PSA_ERROR_BAD_STATE;
                }
                hash_len = wc_HashGetDigestSize(wolfpsa_hash_type_from_alg(ctx->alg));
                if (hash_len <= 0 || data_length != (size_t)hash_len) {
                    return PSA_ERROR_INVALID_ARGUMENT;
                }
            }
            if (step == PSA_KEY_DERIVATION_INPUT_INFO &&
                (ctx->steps_set & WOLFPSA_KDF_STEP_SECRET) == 0) {
                return PSA_ERROR_BAD_STATE;
            }
            return PSA_SUCCESS;
        }

        if (PSA_ALG_IS_HKDF(ctx->alg)) {
            if (step == PSA_KEY_DERIVATION_INPUT_SALT) {
                if ((ctx->steps_set & WOLFPSA_KDF_STEP_SECRET) != 0) {
                    return PSA_ERROR_BAD_STATE;
                }
                return PSA_SUCCESS;
            }
            if (step == PSA_KEY_DERIVATION_INPUT_SECRET) {
                if ((ctx->steps_set & WOLFPSA_KDF_STEP_SECRET) != 0) {
                    return PSA_ERROR_BAD_STATE;
                }
                return PSA_SUCCESS;
            }
            if (step == PSA_KEY_DERIVATION_INPUT_INFO) {
                return PSA_SUCCESS;
            }
        }

        return PSA_ERROR_INVALID_ARGUMENT;
    }
    else if (PSA_ALG_IS_TLS12_PRF(ctx->alg)) {
        if (step != PSA_KEY_DERIVATION_INPUT_SECRET &&
            step != PSA_KEY_DERIVATION_INPUT_LABEL &&
            step != PSA_KEY_DERIVATION_INPUT_SEED) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        return PSA_SUCCESS;
    }
    else if (PSA_ALG_IS_TLS12_PSK_TO_MS(ctx->alg)) {
        if (step != PSA_KEY_DERIVATION_INPUT_SECRET &&
            step != PSA_KEY_DERIVATION_INPUT_OTHER_SECRET &&
            step != PSA_KEY_DERIVATION_INPUT_SEED) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (step == PSA_KEY_DERIVATION_INPUT_SECRET) {
            if ((ctx->steps_set & WOLFPSA_KDF_STEP_SEED) == 0 ||
                (ctx->steps_set & WOLFPSA_KDF_STEP_OTHER_SECRET) == 0) {
                return PSA_ERROR_BAD_STATE;
            }
        }
        if (step == PSA_KEY_DERIVATION_INPUT_OTHER_SECRET &&
            (ctx->steps_set & WOLFPSA_KDF_STEP_SEED) == 0) {
            return PSA_ERROR_BAD_STATE;
        }
        return PSA_SUCCESS;
    }
    else if (PSA_ALG_IS_PBKDF2(ctx->alg)) {
        if (step != PSA_KEY_DERIVATION_INPUT_PASSWORD &&
            step != PSA_KEY_DERIVATION_INPUT_SALT) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        return PSA_SUCCESS;
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_derivation_setup(psa_key_derivation_operation_t *operation,
                                      psa_algorithm_t alg)
{
    wolfpsa_kdf_ctx_t *ctx;
    psa_algorithm_t kdf_alg = alg;
    int hash_type;

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (operation->opaque != (uintptr_t)NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    if (!PSA_ALG_IS_KEY_DERIVATION_OR_AGREEMENT(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (PSA_ALG_IS_KEY_AGREEMENT(alg)) {
        if (PSA_ALG_KEY_AGREEMENT_GET_BASE(alg) != PSA_ALG_ECDH) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        kdf_alg = PSA_ALG_KEY_AGREEMENT_GET_KDF(alg);
    }

    if (!(PSA_ALG_IS_ANY_HKDF(kdf_alg) || PSA_ALG_IS_TLS12_PRF(kdf_alg) ||
          PSA_ALG_IS_TLS12_PSK_TO_MS(kdf_alg) || PSA_ALG_IS_PBKDF2(kdf_alg) ||
          kdf_alg == PSA_ALG_CATEGORY_KEY_DERIVATION)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (PSA_ALG_IS_ANY_HKDF(kdf_alg) || PSA_ALG_IS_TLS12_PRF(kdf_alg) ||
        PSA_ALG_IS_TLS12_PSK_TO_MS(kdf_alg) || PSA_ALG_IS_PBKDF2_HMAC(kdf_alg)) {
        hash_type = wolfpsa_hash_type_from_alg(kdf_alg);
        if (hash_type == WC_HASH_TYPE_NONE) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
    }

    ctx = (wolfpsa_kdf_ctx_t *)XMALLOC(sizeof(*ctx), NULL,
                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    XMEMSET(ctx, 0, sizeof(*ctx));
    ctx->alg = kdf_alg;
    if (PSA_ALG_IS_KEY_AGREEMENT(alg)) {
        ctx->is_key_agreement = 1;
        ctx->ka_alg = PSA_ALG_KEY_AGREEMENT_GET_BASE(alg);
        if (kdf_alg == PSA_ALG_CATEGORY_KEY_DERIVATION) {
            ctx->is_raw_kdf = 1;
        }
    }
    ctx->capacity = PSA_KEY_DERIVATION_UNLIMITED_CAPACITY;

    operation->opaque = (uintptr_t)ctx;
    return PSA_SUCCESS;
}

psa_status_t psa_key_derivation_abort(psa_key_derivation_operation_t *operation)
{
    wolfpsa_kdf_ctx_t *ctx = wolfpsa_kdf_get_ctx(operation);

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (ctx != NULL) {
        wolfpsa_kdf_free_buf(&ctx->secret, &ctx->secret_length);
        wolfpsa_kdf_free_buf(&ctx->other_secret, &ctx->other_secret_length);
        wolfpsa_kdf_free_buf(&ctx->salt, &ctx->salt_length);
        wolfpsa_kdf_free_buf(&ctx->info, &ctx->info_length);
        wolfpsa_kdf_free_buf(&ctx->label, &ctx->label_length);
        wolfpsa_kdf_free_buf(&ctx->seed, &ctx->seed_length);
        wolfpsa_kdf_free_buf(&ctx->password, &ctx->password_length);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        operation->opaque = (uintptr_t)NULL;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_key_derivation_set_capacity(psa_key_derivation_operation_t *operation,
                                             size_t capacity)
{
    wolfpsa_kdf_ctx_t *ctx = wolfpsa_kdf_get_ctx(operation);
    int hash_len;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    if (PSA_ALG_IS_ANY_HKDF(ctx->alg)) {
        hash_len = wc_HashGetDigestSize(wolfpsa_hash_type_from_alg(ctx->alg));
        if (hash_len <= 0) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        if (PSA_ALG_IS_HKDF_EXTRACT(ctx->alg)) {
            if (capacity > (size_t)hash_len) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
        }
        else if (capacity > (size_t)(255u * (size_t)hash_len)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    ctx->capacity = capacity;
    return PSA_SUCCESS;
}

psa_status_t psa_key_derivation_get_capacity(const psa_key_derivation_operation_t *operation,
                                             size_t *capacity)
{
    const wolfpsa_kdf_ctx_t *ctx;

    if (operation == NULL || capacity == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    ctx = (const wolfpsa_kdf_ctx_t *)(uintptr_t)operation->opaque;
    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    *capacity = ctx->capacity;
    return PSA_SUCCESS;
}

psa_status_t psa_key_derivation_input_bytes(psa_key_derivation_operation_t *operation,
                                            psa_key_derivation_step_t step,
                                            const uint8_t *data,
                                            size_t data_length)
{
    wolfpsa_kdf_ctx_t *ctx = wolfpsa_kdf_get_ctx(operation);
    psa_status_t status;
    uint32_t mask;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    status = wolfpsa_kdf_validate_step(ctx, step, data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    mask = wolfpsa_kdf_step_mask(step);
    if (mask == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    switch (step) {
        case PSA_KEY_DERIVATION_INPUT_SECRET:
            status = wolfpsa_kdf_append(&ctx->secret, &ctx->secret_length,
                                        data, data_length);
            break;
        case PSA_KEY_DERIVATION_INPUT_OTHER_SECRET:
            status = wolfpsa_kdf_append(&ctx->other_secret, &ctx->other_secret_length,
                                        data, data_length);
            break;
        case PSA_KEY_DERIVATION_INPUT_SALT:
            status = wolfpsa_kdf_append(&ctx->salt, &ctx->salt_length,
                                        data, data_length);
            break;
        case PSA_KEY_DERIVATION_INPUT_INFO:
            status = wolfpsa_kdf_append(&ctx->info, &ctx->info_length,
                                        data, data_length);
            break;
        case PSA_KEY_DERIVATION_INPUT_LABEL:
            status = wolfpsa_kdf_append(&ctx->label, &ctx->label_length,
                                        data, data_length);
            break;
        case PSA_KEY_DERIVATION_INPUT_SEED:
            status = wolfpsa_kdf_append(&ctx->seed, &ctx->seed_length,
                                        data, data_length);
            break;
        case PSA_KEY_DERIVATION_INPUT_PASSWORD:
            status = wolfpsa_kdf_append(&ctx->password, &ctx->password_length,
                                        data, data_length);
            break;
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (status == PSA_SUCCESS) {
        ctx->steps_set |= mask;
    }
    return status;
}

psa_status_t psa_key_derivation_input_integer(psa_key_derivation_operation_t *operation,
                                              psa_key_derivation_step_t step,
                                              uint64_t value)
{
    wolfpsa_kdf_ctx_t *ctx = wolfpsa_kdf_get_ctx(operation);

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    if (ctx->output_started) {
        return PSA_ERROR_BAD_STATE;
    }

    if (step != PSA_KEY_DERIVATION_INPUT_COST) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!PSA_ALG_IS_PBKDF2(ctx->alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (value > 0xFFFFFFFFu) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    ctx->cost = (uint32_t)value;
    ctx->steps_set |= WOLFPSA_KDF_STEP_COST;
    return PSA_SUCCESS;
}

psa_status_t psa_key_derivation_input_key(psa_key_derivation_operation_t *operation,
                                          psa_key_derivation_step_t step,
                                          psa_key_id_t key)
{
    wolfpsa_kdf_ctx_t *ctx = wolfpsa_kdf_get_ctx(operation);
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_algorithm_t key_alg;
    psa_status_t status;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    status = wolfpsa_get_key_data(key, &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = wolfpsa_kdf_validate_step(ctx, step, key_data_length);
    if (status != PSA_SUCCESS) {
        wolfpsa_free_key_data(key_data);
        return status;
    }

    if ((psa_get_key_usage_flags(&attributes) &
         (PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_VERIFY_DERIVATION)) == 0) {
        wolfpsa_free_key_data(key_data);
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (PSA_ALG_IS_PBKDF2(ctx->alg)) {
        if (step != PSA_KEY_DERIVATION_INPUT_PASSWORD ||
            psa_get_key_type(&attributes) != PSA_KEY_TYPE_PASSWORD) {
            wolfpsa_free_key_data(key_data);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else if (step == PSA_KEY_DERIVATION_INPUT_SECRET ||
             step == PSA_KEY_DERIVATION_INPUT_OTHER_SECRET) {
        if (psa_get_key_type(&attributes) != PSA_KEY_TYPE_DERIVE) {
            wolfpsa_free_key_data(key_data);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else {
        wolfpsa_free_key_data(key_data);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_alg = psa_get_key_algorithm(&attributes);
    if (key_alg != PSA_ALG_NONE) {
        if (ctx->is_key_agreement) {
            if (!PSA_ALG_IS_KEY_AGREEMENT(key_alg) ||
                PSA_ALG_KEY_AGREEMENT_GET_KDF(key_alg) != ctx->alg) {
                wolfpsa_free_key_data(key_data);
                return PSA_ERROR_NOT_PERMITTED;
            }
        }
        else if (key_alg != ctx->alg) {
            wolfpsa_free_key_data(key_data);
            return PSA_ERROR_NOT_PERMITTED;
        }
    }

    status = psa_key_derivation_input_bytes(operation, step,
                                            key_data, key_data_length);
    wolfpsa_free_key_data(key_data);
    return status;
}

psa_status_t psa_key_derivation_key_agreement(psa_key_derivation_operation_t *operation,
                                              psa_key_derivation_step_t step,
                                              psa_key_id_t private_key,
                                              const uint8_t *peer_key,
                                              size_t peer_key_length)
{
    wolfpsa_kdf_ctx_t *ctx = wolfpsa_kdf_get_ctx(operation);
    psa_key_attributes_t priv_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;
    size_t secret_len;
    size_t output_len = 0;
    uint8_t *secret = NULL;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (!ctx->is_key_agreement) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (ctx->output_started) {
        return PSA_ERROR_BAD_STATE;
    }
    if (step != PSA_KEY_DERIVATION_INPUT_SECRET &&
        step != PSA_KEY_DERIVATION_INPUT_OTHER_SECRET) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (step == PSA_KEY_DERIVATION_INPUT_OTHER_SECRET &&
        !PSA_ALG_IS_TLS12_PSK_TO_MS(ctx->alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = psa_get_key_attributes(private_key, &priv_attr);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if ((psa_get_key_usage_flags(&priv_attr) & PSA_KEY_USAGE_DERIVE) == 0) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (!PSA_KEY_TYPE_IS_KEY_PAIR(psa_get_key_type(&priv_attr))) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    secret_len = PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(psa_get_key_type(&priv_attr),
                                                   psa_get_key_bits(&priv_attr));
    if (secret_len == 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    secret = (uint8_t *)XMALLOC(secret_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (secret == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    status = psa_raw_key_agreement(ctx->ka_alg, private_key,
                                   peer_key, peer_key_length,
                                   secret, secret_len, &output_len);
    if (status == PSA_SUCCESS) {
        status = psa_key_derivation_input_bytes(operation,
                                                step,
                                                secret, output_len);
    }

    XFREE(secret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return status;
}

static psa_status_t wolfpsa_kdf_hkdf(wolfpsa_kdf_ctx_t *ctx,
                                     uint8_t *output,
                                     size_t output_length)
{
    int hash_type = wolfpsa_hash_type_from_alg(ctx->alg);
    int ret;

    if (hash_type == WC_HASH_TYPE_NONE) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (PSA_ALG_IS_HKDF_EXTRACT(ctx->alg)) {
        int hash_len = wc_HashGetDigestSize(hash_type);
        if (hash_len <= 0) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        if (output_length != (size_t)hash_len) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        ret = wc_HKDF_Extract(hash_type,
                              ctx->salt, (word32)ctx->salt_length,
                              ctx->secret, (word32)ctx->secret_length,
                              output);
        return ret == 0 ? PSA_SUCCESS : wc_error_to_psa_status(ret);
    }

    if (PSA_ALG_IS_HKDF_EXPAND(ctx->alg)) {
        ret = wc_HKDF_Expand(hash_type,
                             ctx->secret, (word32)ctx->secret_length,
                             ctx->info, (word32)ctx->info_length,
                             output, (word32)output_length);
        return ret == 0 ? PSA_SUCCESS : wc_error_to_psa_status(ret);
    }

    if (PSA_ALG_IS_HKDF(ctx->alg)) {
        int hash_len = wc_HashGetDigestSize(hash_type);
        uint8_t prk[WC_MAX_DIGEST_SIZE];

        if (hash_len <= 0 || (size_t)hash_len > sizeof(prk)) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        ret = wc_HKDF_Extract(hash_type,
                              ctx->salt, (word32)ctx->salt_length,
                              ctx->secret, (word32)ctx->secret_length,
                              prk);
        if (ret != 0) {
            return wc_error_to_psa_status(ret);
        }

        ret = wc_HKDF_Expand(hash_type,
                             prk, (word32)hash_len,
                             ctx->info, (word32)ctx->info_length,
                             output, (word32)output_length);
        if (ret != 0) {
            return wc_error_to_psa_status(ret);
        }
        return PSA_SUCCESS;
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t wolfpsa_kdf_tls12_prf(wolfpsa_kdf_ctx_t *ctx,
                                          uint8_t *output,
                                          size_t output_length)
{
    int hash_type = wolfpsa_hash_type_from_alg(ctx->alg);
    int ret;

    if (hash_type == WC_HASH_TYPE_NONE) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    ret = wc_PRF_TLS(output, (word32)output_length,
                     ctx->secret, (word32)ctx->secret_length,
                     ctx->label, (word32)ctx->label_length,
                     ctx->seed, (word32)ctx->seed_length,
                     1, hash_type, NULL, INVALID_DEVID);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    return PSA_SUCCESS;
}

static psa_status_t wolfpsa_kdf_tls12_psk_to_ms(wolfpsa_kdf_ctx_t *ctx,
                                                uint8_t *output,
                                                size_t output_length)
{
    int hash_type = wolfpsa_hash_type_from_alg(ctx->alg);
    uint8_t *premaster = NULL;
    size_t premaster_len;
    psa_status_t status;
    int ret;

    if (hash_type == WC_HASH_TYPE_NONE) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    premaster_len = 2u + ctx->secret_length + 2u + ctx->other_secret_length;
    premaster = (uint8_t *)XMALLOC(premaster_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (premaster == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    premaster[0] = (uint8_t)((ctx->secret_length >> 8) & 0xff);
    premaster[1] = (uint8_t)(ctx->secret_length & 0xff);
    XMEMCPY(premaster + 2u, ctx->secret, ctx->secret_length);
    premaster[2u + ctx->secret_length] = (uint8_t)((ctx->other_secret_length >> 8) & 0xff);
    premaster[3u + ctx->secret_length] = (uint8_t)(ctx->other_secret_length & 0xff);
    XMEMCPY(premaster + 4u + ctx->secret_length, ctx->other_secret,
            ctx->other_secret_length);

    ret = wc_PRF_TLS(output, (word32)output_length,
                     premaster, (word32)premaster_len,
                     (const byte *)"master secret", 13u,
                     ctx->seed, (word32)ctx->seed_length,
                     1, hash_type, NULL, INVALID_DEVID);
    if (ret != 0) {
        status = wc_error_to_psa_status(ret);
    }
    else {
        status = PSA_SUCCESS;
    }

    XFREE(premaster, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return status;
}

static psa_status_t wolfpsa_kdf_pbkdf2(wolfpsa_kdf_ctx_t *ctx,
                                       uint8_t *output,
                                       size_t output_length)
{
    if (PSA_ALG_IS_PBKDF2_HMAC(ctx->alg)) {
        int hash_type = wolfpsa_hash_type_from_alg(ctx->alg);
        int ret;

        if (hash_type == WC_HASH_TYPE_NONE) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        ret = wc_PBKDF2(output, ctx->password, (int)ctx->password_length,
                        ctx->salt, (int)ctx->salt_length,
                        (int)ctx->cost, (int)output_length, hash_type);
        if (ret != 0) {
            return wc_error_to_psa_status(ret);
        }
        return PSA_SUCCESS;
    }

    if (ctx->alg == PSA_ALG_PBKDF2_AES_CMAC_PRF_128) {
#if defined(WOLFSSL_CMAC) && !defined(NO_AES)
        uint8_t prf_key[WC_AES_BLOCK_SIZE];
        uint8_t u_block[WC_AES_BLOCK_SIZE];
        uint8_t t_block[WC_AES_BLOCK_SIZE];
        uint8_t *block_input = NULL;
        uint8_t zero_key[WC_AES_BLOCK_SIZE];
        size_t blocks;
        size_t block_input_len;
        size_t offset = 0;
        uint32_t i;
        uint32_t j;
        int ret;
        Cmac cmac;
        word32 out_sz = WC_AES_BLOCK_SIZE;

        XMEMSET(zero_key, 0, sizeof(zero_key));
        ret = wc_InitCmac(&cmac, zero_key, (word32)sizeof(zero_key),
                          WC_CMAC_AES, NULL);
        if (ret != 0) {
            return wc_error_to_psa_status(ret);
        }
        ret = wc_CmacUpdate(&cmac, ctx->password, (word32)ctx->password_length);
        if (ret != 0) {
            wc_CmacFree(&cmac);
            return wc_error_to_psa_status(ret);
        }
        ret = wc_CmacFinal(&cmac, prf_key, &out_sz);
        wc_CmacFree(&cmac);
        if (ret != 0 || out_sz != WC_AES_BLOCK_SIZE) {
            return ret == 0 ? PSA_ERROR_NOT_SUPPORTED : wc_error_to_psa_status(ret);
        }

        block_input_len = ctx->salt_length + 4;
        block_input = (uint8_t *)XMALLOC(block_input_len, NULL,
                                         DYNAMIC_TYPE_TMP_BUFFER);
        if (block_input == NULL) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }

        blocks = (output_length + WC_AES_BLOCK_SIZE - 1) / WC_AES_BLOCK_SIZE;
        for (i = 1; i <= blocks; i++) {
            XMEMCPY(block_input, ctx->salt, ctx->salt_length);
            block_input[ctx->salt_length + 0] = (uint8_t)((i >> 24) & 0xff);
            block_input[ctx->salt_length + 1] = (uint8_t)((i >> 16) & 0xff);
            block_input[ctx->salt_length + 2] = (uint8_t)((i >> 8) & 0xff);
            block_input[ctx->salt_length + 3] = (uint8_t)(i & 0xff);

            ret = wc_InitCmac(&cmac, prf_key, (word32)sizeof(prf_key),
                              WC_CMAC_AES, NULL);
            if (ret != 0) {
                XFREE(block_input, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                return wc_error_to_psa_status(ret);
            }
            out_sz = WC_AES_BLOCK_SIZE;
            ret = wc_CmacUpdate(&cmac, block_input, (word32)block_input_len);
            if (ret == 0) {
                ret = wc_CmacFinal(&cmac, u_block, &out_sz);
            }
            wc_CmacFree(&cmac);
            if (ret != 0 || out_sz != WC_AES_BLOCK_SIZE) {
                XFREE(block_input, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                return ret == 0 ? PSA_ERROR_NOT_SUPPORTED : wc_error_to_psa_status(ret);
            }

            XMEMCPY(t_block, u_block, WC_AES_BLOCK_SIZE);
            for (j = 1; j < ctx->cost; j++) {
                ret = wc_InitCmac(&cmac, prf_key, (word32)sizeof(prf_key),
                                  WC_CMAC_AES, NULL);
                if (ret != 0) {
                    XFREE(block_input, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    return wc_error_to_psa_status(ret);
                }
                out_sz = WC_AES_BLOCK_SIZE;
                ret = wc_CmacUpdate(&cmac, u_block, WC_AES_BLOCK_SIZE);
                if (ret == 0) {
                    ret = wc_CmacFinal(&cmac, u_block, &out_sz);
                }
                wc_CmacFree(&cmac);
                if (ret != 0 || out_sz != WC_AES_BLOCK_SIZE) {
                    XFREE(block_input, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    return ret == 0 ? PSA_ERROR_NOT_SUPPORTED : wc_error_to_psa_status(ret);
                }
                t_block[0] ^= u_block[0];
                t_block[1] ^= u_block[1];
                t_block[2] ^= u_block[2];
                t_block[3] ^= u_block[3];
                t_block[4] ^= u_block[4];
                t_block[5] ^= u_block[5];
                t_block[6] ^= u_block[6];
                t_block[7] ^= u_block[7];
                t_block[8] ^= u_block[8];
                t_block[9] ^= u_block[9];
                t_block[10] ^= u_block[10];
                t_block[11] ^= u_block[11];
                t_block[12] ^= u_block[12];
                t_block[13] ^= u_block[13];
                t_block[14] ^= u_block[14];
                t_block[15] ^= u_block[15];
            }

            if (offset + WC_AES_BLOCK_SIZE <= output_length) {
                XMEMCPY(output + offset, t_block, WC_AES_BLOCK_SIZE);
                offset += WC_AES_BLOCK_SIZE;
            }
            else {
                XMEMCPY(output + offset, t_block, output_length - offset);
                offset = output_length;
            }
        }
        XFREE(block_input, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return PSA_SUCCESS;
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_derivation_output_bytes(psa_key_derivation_operation_t *operation,
                                             uint8_t *output,
                                             size_t output_length)
{
    wolfpsa_kdf_ctx_t *ctx = wolfpsa_kdf_get_ctx(operation);
    psa_status_t status;

    if (ctx == NULL || output == NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    if (ctx->is_raw_kdf) {
        if ((ctx->steps_set & WOLFPSA_KDF_STEP_SECRET) == 0 ||
            output_length > ctx->secret_length) {
            return PSA_ERROR_INSUFFICIENT_DATA;
        }
    }
    else if (PSA_ALG_IS_ANY_HKDF(ctx->alg)) {
        if (PSA_ALG_IS_HKDF_EXTRACT(ctx->alg)) {
            if ((ctx->steps_set & WOLFPSA_KDF_STEP_SECRET) == 0 ||
                (ctx->steps_set & WOLFPSA_KDF_STEP_SALT) == 0) {
                return PSA_ERROR_BAD_STATE;
            }
        }
        else if (PSA_ALG_IS_HKDF_EXPAND(ctx->alg)) {
            if ((ctx->steps_set & WOLFPSA_KDF_STEP_SECRET) == 0 ||
                (ctx->steps_set & WOLFPSA_KDF_STEP_INFO) == 0) {
                return PSA_ERROR_BAD_STATE;
            }
        }
        else {
            if ((ctx->steps_set & WOLFPSA_KDF_STEP_SECRET) == 0 ||
                (ctx->steps_set & WOLFPSA_KDF_STEP_INFO) == 0) {
                return PSA_ERROR_BAD_STATE;
            }
        }
    }
    else if (PSA_ALG_IS_TLS12_PRF(ctx->alg)) {
        if ((ctx->steps_set & WOLFPSA_KDF_STEP_SECRET) == 0 ||
            (ctx->steps_set & WOLFPSA_KDF_STEP_LABEL) == 0 ||
            (ctx->steps_set & WOLFPSA_KDF_STEP_SEED) == 0) {
            return PSA_ERROR_BAD_STATE;
        }
    }
    else if (PSA_ALG_IS_TLS12_PSK_TO_MS(ctx->alg)) {
        if ((ctx->steps_set & WOLFPSA_KDF_STEP_SECRET) == 0 ||
            (ctx->steps_set & WOLFPSA_KDF_STEP_OTHER_SECRET) == 0 ||
            (ctx->steps_set & WOLFPSA_KDF_STEP_SEED) == 0) {
            return PSA_ERROR_BAD_STATE;
        }
    }
    else if (PSA_ALG_IS_PBKDF2(ctx->alg)) {
        if ((ctx->steps_set & WOLFPSA_KDF_STEP_PASSWORD) == 0 ||
            (ctx->steps_set & WOLFPSA_KDF_STEP_SALT) == 0 ||
            (ctx->steps_set & WOLFPSA_KDF_STEP_COST) == 0) {
            return PSA_ERROR_BAD_STATE;
        }
    }

    status = wolfpsa_kdf_require_output(ctx, output_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    ctx->output_started = 1;

    if (ctx->is_raw_kdf) {
        XMEMCPY(output, ctx->secret, output_length);
        return PSA_SUCCESS;
    }

    if (PSA_ALG_IS_ANY_HKDF(ctx->alg)) {
        return wolfpsa_kdf_hkdf(ctx, output, output_length);
    }
    if (PSA_ALG_IS_TLS12_PRF(ctx->alg)) {
        return wolfpsa_kdf_tls12_prf(ctx, output, output_length);
    }
    if (PSA_ALG_IS_TLS12_PSK_TO_MS(ctx->alg)) {
        return wolfpsa_kdf_tls12_psk_to_ms(ctx, output, output_length);
    }
    if (PSA_ALG_IS_PBKDF2(ctx->alg)) {
        return wolfpsa_kdf_pbkdf2(ctx, output, output_length);
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_derivation_output_key(const psa_key_attributes_t *attributes,
                                           psa_key_derivation_operation_t *operation,
                                           psa_key_id_t *key)
{
    size_t key_len;
    uint8_t *buffer;
    psa_status_t status;

    if (attributes == NULL || key == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!PSA_KEY_TYPE_IS_UNSTRUCTURED(attributes->type)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_len = PSA_BITS_TO_BYTES(attributes->bits);
    if (key_len == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    buffer = (uint8_t *)XMALLOC(key_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buffer == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    status = psa_key_derivation_output_bytes(operation, buffer, key_len);
    if (status != PSA_SUCCESS) {
        XFREE(buffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return status;
    }

    status = psa_import_key(attributes, buffer, key_len, key);
    XFREE(buffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return status;
}

psa_status_t psa_key_derivation_verify_bytes(psa_key_derivation_operation_t *operation,
                                             const uint8_t *expected,
                                             size_t expected_length)
{
    uint8_t *buffer;
    psa_status_t status;

    if (expected == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    buffer = (uint8_t *)XMALLOC(expected_length, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buffer == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    status = psa_key_derivation_output_bytes(operation, buffer, expected_length);
    if (status != PSA_SUCCESS) {
        XFREE(buffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return status;
    }

    if (ConstantCompare(buffer, expected, (int)expected_length) != 0) {
        status = PSA_ERROR_INVALID_SIGNATURE;
    }
    else {
        status = PSA_SUCCESS;
    }

    XFREE(buffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return status;
}

psa_status_t psa_key_derivation_verify_key(psa_key_derivation_operation_t *operation,
                                           psa_key_id_t expected)
{
    uint8_t *expected_data = NULL;
    size_t expected_length = 0;
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    wolfpsa_kdf_ctx_t *ctx = wolfpsa_kdf_get_ctx(operation);

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    status = psa_get_key_attributes(expected, &attributes);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if ((psa_get_key_usage_flags(&attributes) & PSA_KEY_USAGE_VERIFY_DERIVATION) == 0) {
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (PSA_ALG_IS_PBKDF2(ctx->alg) &&
        psa_get_key_type(&attributes) != PSA_KEY_TYPE_PASSWORD_HASH) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = wolfpsa_get_key_data(expected, NULL, &expected_data, &expected_length);
    if (status != PSA_SUCCESS) {
        wolfpsa_free_key_data(expected_data);
        return status;
    }

    status = psa_key_derivation_verify_bytes(operation, expected_data,
                                             expected_length);
    wolfpsa_free_key_data(expected_data);
    return status;
}

#endif /* WOLFSSL_PSA_ENGINE */
