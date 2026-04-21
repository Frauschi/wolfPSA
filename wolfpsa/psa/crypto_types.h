/* crypto_types.h
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

#ifndef PSA_CRYPTO_TYPES_H
#define PSA_CRYPTO_TYPES_H

#include <stddef.h>
#include <stdint.h>


#ifndef PSA_SUCCESS
typedef int32_t psa_status_t;
#endif

typedef uint16_t psa_key_type_t;
typedef uint8_t psa_ecc_family_t;
typedef uint8_t psa_dh_family_t;
typedef uint32_t psa_algorithm_t;
typedef uint32_t psa_key_lifetime_t;
typedef uint8_t psa_key_persistence_t;
typedef uint32_t psa_key_location_t;
typedef uint32_t psa_key_id_t;
typedef uint32_t psa_key_usage_t;
typedef uint16_t psa_key_derivation_step_t;
typedef uint32_t psa_pake_primitive_t;
typedef uint8_t psa_pake_primitive_type_t;
typedef uint8_t psa_pake_family_t;
typedef uint8_t psa_pake_role_t;
typedef uint8_t psa_pake_step_t;

typedef struct psa_key_attributes_s psa_key_attributes_t;
typedef struct psa_custom_key_parameters_s psa_custom_key_parameters_t;
typedef struct psa_pake_cipher_suite_s psa_pake_cipher_suite_t;
typedef struct psa_pake_operation_s psa_pake_operation_t;

#endif 
