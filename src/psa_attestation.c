/* psa_attestation.c
 *
 * Stub PSA initial attestation APIs.
 *
 * Copyright (C) 2026 wolfSSL Inc.
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

#include <stddef.h>
#include <stdint.h>

#include "psa/initial_attestation.h"

psa_status_t psa_initial_attest_get_token(const uint8_t *auth_challenge,
					  size_t challenge_size,
					  uint8_t *token_buf,
					  size_t token_buf_size,
					  size_t *token_size)
{
	(void)auth_challenge;
	(void)challenge_size;
	(void)token_buf;
	(void)token_buf_size;
	if (token_size != NULL) {
		*token_size = 0;
	}
	return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_initial_attest_get_token_size(size_t challenge_size,
					       size_t *token_size)
{
	(void)challenge_size;
	if (token_size != NULL) {
		*token_size = 0;
	}
	return PSA_ERROR_NOT_SUPPORTED;
}
