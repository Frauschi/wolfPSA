# Changelog

## v5.9.1

Initial official release of `wolfPSA`. This project follows wolfSSL version numbering.

- First public wolfPSA release: a PSA Crypto engine implemented in C on top of wolfCrypt.
- Provides PSA Crypto API entry points intended for PSA clients such as wolfSSL built with `WOLFSSL_HAVE_PSA` and the Arm PSA Architecture Test Suite.
- Ships both static and shared builds: `libwolfpsa.a` and `libwolfpsa.so`.
- Includes core PSA lifecycle, random generation, key management, key storage, cipher, AEAD, hash, MAC, asymmetric crypto, key derivation, and TLS 1.3 PRF/HKDF support.
- Symmetric crypto coverage includes AES, ChaCha20, ChaCha20-Poly1305, and configured legacy compatibility paths such as DES/3DES where enabled.
- Hash and MAC support includes SHA-1, SHA-2, SHA-3, HMAC, CMAC, plus configured compatibility support for MD5 and RIPEMD-160.
- Asymmetric crypto support includes RSA, ECC/ECDSA/ECDH, Curve25519/Curve448, and Ed25519/Ed448.
- Includes persistent PSA key storage with a default POSIX filesystem-backed store for local and test deployments.
- Includes post-quantum and hash-based crypto integration sources for builds that enable wolfCrypt support, including ML-KEM, ML-DSA, LMS, and XMSS.
- Includes standalone integration tests and demos for PSA API calls, PSA-backed wolfCrypt benchmarking, and a TLS server/client flow using PSA-managed keys and certificate pinning.
- Includes target integration and scripts for running the Arm PSA Architecture Test Suite; current documented crypto results are 65 passed tests, 13 skipped, and 0 failed.
