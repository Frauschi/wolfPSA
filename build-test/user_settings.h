/* user_settings.h
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

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

/* The build-config-matrix harness drives every algorithm feature via
 * wolfcrypt-native defines passed on the compiler command line by
 * build-test/build-variant.sh. This file only sets up invariants that are
 * always required (or always forbidden) regardless of the lane. */

#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define WOLFSSL_PSA_ENGINE
#define NO_DSA

#endif /* WOLFSSL_USER_SETTINGS_H */
