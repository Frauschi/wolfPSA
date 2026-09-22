/* user_settings.h
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

/*
 * wolfPSA / wolfSSL TLS coexistence settings file.
 *
 * The example feature set minus WOLFCRYPT_ONLY, so the wolfSSL TLS layer stays
 * in the build (psa_tls_coexist exercises TLS and wolfPSA on one shared
 * wolfCrypt core). Inherited rather than forked: a macro added to the example
 * must reach this target too.
 *
 * Point CONFIG_WOLFSSL_SETTINGS_FILE at it (the wolfPSA module root is on the
 * include path, so this zephyr/-relative name resolves):
 *
 *     CONFIG_WOLFSSL_SETTINGS_FILE="zephyr/tests/psa_tls_coexist/user_settings.h"
 */

#ifndef USER_SETTINGS_WOLFPSA_TLS_COEXIST_H
#define USER_SETTINGS_WOLFPSA_TLS_COEXIST_H

#include "zephyr/user_settings_example.h"

/* The only divergence: keep the TLS layer. */
#undef WOLFCRYPT_ONLY

#endif /* USER_SETTINGS_WOLFPSA_TLS_COEXIST_H */
