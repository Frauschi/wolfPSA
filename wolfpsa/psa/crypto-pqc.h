/* crypto-pqc.h
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
#ifndef PSA_CRYPTO_PQC_H
#define PSA_CRYPTO_PQC_H
typedef uint8_t psa_slh_dsa_family_t;

#define PSA_ALG_SHA_256_192 ((psa_algorithm_t)0x0200000E)
#define PSA_ALG_SHAKE128_256 ((psa_algorithm_t)0x02000016)
#define PSA_ALG_SHAKE256_192 ((psa_algorithm_t)0x02000017)
#define PSA_ALG_SHAKE256_256 ((psa_algorithm_t)0x02000018)
#define PSA_KEY_TYPE_ML_KEM_KEY_PAIR ((psa_key_type_t)0x7004)
#define PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY ((psa_key_type_t)0x4004)
#define PSA_KEY_TYPE_IS_ML_KEM(type) 
#define PSA_ALG_ML_KEM ((psa_algorithm_t)0x0c000200)
#define PSA_KEY_TYPE_ML_DSA_KEY_PAIR ((psa_key_type_t)0x7002)
#define PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY ((psa_key_type_t)0x4002)
#define PSA_KEY_TYPE_IS_ML_DSA(type) 
#define PSA_ALG_ML_DSA ((psa_algorithm_t) 0x06004400)
#define PSA_ALG_DETERMINISTIC_ML_DSA ((psa_algorithm_t) 0x06004500)
#define PSA_ALG_HASH_ML_DSA(hash_alg) 
#define PSA_ALG_IS_ML_DSA(alg) 
#define PSA_ALG_IS_HASH_ML_DSA(alg) 
#define PSA_ALG_IS_DETERMINISTIC_HASH_ML_DSA(alg) 

#define PSA_ALG_IS_HEDGED_HASH_ML_DSA(alg) 
#define PSA_KEY_TYPE_SLH_DSA_KEY_PAIR(set) 
#define PSA_KEY_TYPE_SLH_DSA_PUBLIC_KEY(set) 
#define PSA_SLH_DSA_FAMILY_SHA2_S ((psa_slh_dsa_family_t) 0x02)
#define PSA_SLH_DSA_FAMILY_SHA2_F ((psa_slh_dsa_family_t) 0x04)
#define PSA_SLH_DSA_FAMILY_SHAKE_S ((psa_slh_dsa_family_t) 0x0b)
#define PSA_SLH_DSA_FAMILY_SHAKE_F ((psa_slh_dsa_family_t) 0x0d)
#define PSA_KEY_TYPE_IS_SLH_DSA(type) 
#define PSA_KEY_TYPE_SLH_DSA_GET_FAMILY(type) 
#define PSA_ALG_SLH_DSA ((psa_algorithm_t) 0x06004000)
#define PSA_ALG_DETERMINISTIC_SLH_DSA ((psa_algorithm_t) 0x06004100)
#define PSA_ALG_HASH_SLH_DSA(hash_alg) 
#define PSA_ALG_IS_SLH_DSA(alg) 
#define PSA_ALG_IS_HASH_SLH_DSA(alg) 
#define PSA_ALG_IS_HEDGED_HASH_SLH_DSA(alg) 
#define PSA_KEY_TYPE_LMS_PUBLIC_KEY ((psa_key_type_t)0x4007)
#define PSA_KEY_TYPE_HSS_PUBLIC_KEY ((psa_key_type_t)0x4008)
#define PSA_ALG_LMS ((psa_algorithm_t) 0x06004800)
#define PSA_ALG_HSS ((psa_algorithm_t) 0x06004900)
#define PSA_KEY_TYPE_XMSS_PUBLIC_KEY ((psa_key_type_t)0x400B)
#define PSA_KEY_TYPE_XMSS_MT_PUBLIC_KEY ((psa_key_type_t)0x400D)
#define PSA_ALG_XMSS ((psa_algorithm_t) 0x06004A00)
#define PSA_ALG_XMSS_MT ((psa_algorithm_t) 0x06004B00)

#endif /* PSA_CRYPTO_PQC_H */
