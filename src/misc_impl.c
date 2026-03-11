/* misc_impl.c
 *
 * Provide misc.c helper implementations for NO_INLINE builds.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_PSA_ENGINE) && defined(NO_INLINE)
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif
