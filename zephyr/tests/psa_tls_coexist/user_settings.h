/*
 * wolfPSA / wolfSSL TLS coexistence settings file.
 *
 * This is the user_settings_example.h feature set MINUS WOLFCRYPT_ONLY, so the
 * wolfSSL TLS layer stays in the build (the psa_tls_coexist target exercises
 * TLS + wolfPSA on one shared wolfCrypt core). The consttime AES backend
 * (WC_AES_BITSLICED) is required: psa_aead.c fails the build if neither it nor
 * WOLFSSL_AESNI is selected (F-13878), and the module-default Kconfig config
 * (which this target used before) selects neither, so it must come from a
 * settings file.
 *
 * Point CONFIG_WOLFSSL_SETTINGS_FILE at it (the wolfPSA module root is on the
 * include path, so this zephyr/-relative name resolves):
 *
 *     CONFIG_WOLFSSL_SETTINGS_FILE="zephyr/tests/psa_tls_coexist/user_settings.h"
 */

#ifndef USER_SETTINGS_WOLFPSA_TLS_COEXIST_H
#define USER_SETTINGS_WOLFPSA_TLS_COEXIST_H

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Platform / build model                                                    */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_GENERAL_ALIGNMENT 4 /* 32-bit alignment on uint32_t */
#define SIZEOF_LONG_LONG 8
#define WOLFSSL_IGNORE_FILE_WARN
#define NO_WRITEV

/* Structural profile. wolfPSA no longer injects these via Kconfig, so a
 * settings file must set them itself. WOLFCRYPT_ONLY is deliberately NOT set:
 * the TLS layer must coexist with the wolfPSA provider. */
#define HAVE_HASHDRBG               /* wolfPSA requires the Hash-DRBG; the wolfSSL
                                     * module's wc_GenerateSeed() seeds it from the
                                     * HW entropy driver when one is present */
#ifndef CONFIG_MULTITHREADING
    #define SINGLE_THREADED         /* no threading layer available */
#endif

/* ------------------------------------------------------------------------- */
/* Math (Single Precision, all sizes)                                        */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_1024
#define WOLFSSL_SP_384
#define HAVE_SP_ECC

/* ------------------------------------------------------------------------- */
/* RSA                                                                       */
/* ------------------------------------------------------------------------- */
#define RSA_MIN_SIZE 1024
#define WOLFSSL_KEY_GEN
#define WC_RSA_BLINDING
#define WC_RSA_PSS
#define WOLFSSL_PSS_SALT_LEN_DISCOVER
#define WOLFSSL_RSA_OAEP

/* Side-channel hardening for private-key ops. */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT

/* ------------------------------------------------------------------------- */
/* Hashes                                                                    */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_MD5
#define WOLFSSL_RIPEMD
#define WOLFSSL_SHA224
#define WOLFSSL_SHA256
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256
#undef  NO_MD5
#undef  NO_DES3

/* ------------------------------------------------------------------------- */
/* ECC / EdDSA / Montgomery                                                  */
/* ------------------------------------------------------------------------- */
#define HAVE_ECC
#define HAVE_ECC384
#define HAVE_ECC_KEY_EXPORT
#define HAVE_ECC_KEY_IMPORT
#define WOLFSSL_ECDSA_DETERMINISTIC_K
/* PSA places no constraint on the content of the hash passed to
 * psa_sign_hash()/psa_verify_hash(): it is opaque bytes, and an all-zero
 * digest is a legal input (the PSA API test suite signs one for
 * SECP384R1/SHA-384). wolfCrypt rejects an all-zero digest by default as a
 * guard against uninitialized buffers, which would surface as
 * PSA_ERROR_INVALID_ARGUMENT for input the spec requires us to accept. */
#define WC_ALLOW_ECC_ZERO_HASH
#define HAVE_CURVE25519
#define HAVE_ED25519
#define WOLFSSL_ED25519_STREAMING_VERIFY
#define HAVE_CURVE448
#define HAVE_ED448
#define WOLFSSL_ED448_STREAMING_VERIFY

/* ------------------------------------------------------------------------- */
/* Symmetric / AEAD / MAC                                                    */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_DES3
#define WOLFSSL_DES_ECB
#define HAVE_AESGCM
/* Streaming AES-GCM (wc_AesGcmEncryptUpdate) so the multipart AEAD path can
 * emit the payload from psa_aead_update() instead of buffering it all for
 * finish(). */
#define WOLFSSL_AESGCM_STREAM
#define HAVE_AESCCM
#define HAVE_AES_ECB
/* Constant-time AES backend (F-13878): the default software AES uses
 * secret-indexed T-table loads, a cache-timing channel. WC_AES_BITSLICED is
 * the portable consttime core; psa_aead.c fails the build if neither it nor
 * WOLFSSL_AESNI is selected. */
#define WC_AES_BITSLICED
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_CFB
#define WOLFSSL_AES_OFB
#define WOLFSSL_AES_DIRECT          /* required by AES key wrap */
#define HAVE_AES_KEYWRAP
#define WOLFSSL_CMAC
#define HAVE_CHACHA
#define HAVE_XCHACHA
#define HAVE_POLY1305
#define HAVE_ONE_TIME_AUTH

/* ------------------------------------------------------------------------- */
/* KDFs                                                                      */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_HAVE_PRF
#define HAVE_HKDF
#define HAVE_PBKDF2
#define HAVE_CMAC_KDF

/* ------------------------------------------------------------------------- */
/* PQC / stateful-hash                                                       */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_HAVE_MLDSA
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_HAVE_LMS
#define WOLFSSL_LMS_VERIFY_ONLY
#define WOLFSSL_HAVE_XMSS
#define WOLFSSL_XMSS_VERIFY_ONLY

/* ------------------------------------------------------------------------- */
/* Experimental (Ascon requires the opt-in)                                  */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_EXPERIMENTAL_SETTINGS
#define HAVE_ASCON

#ifdef __cplusplus
}
#endif

#endif /* USER_SETTINGS_WOLFPSA_TLS_COEXIST_H */
