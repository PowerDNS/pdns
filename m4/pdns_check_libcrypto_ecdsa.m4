AC_DEFUN([PDNS_CHECK_LIBCRYPTO_ECDSA], [
  AC_REQUIRE([PDNS_CHECK_LIBCRYPTO])
  libcrypto_ecdsa=yes
  AC_CHECK_HEADER([openssl/ecdsa.h], [
    AC_CHECK_DECLS([NID_X9_62_prime256v1, NID_secp384r1], [ : ], [
      libcrypto_ecdsa=no
    ], [AC_INCLUDES_DEFAULT
#include <openssl/evp.h>
    ])
  ], [
    libcrypto_ecdsa=no
  ])

  AS_IF([test "x$libcrypto_ecdsa" = "xyes"], [
    AC_DEFINE([HAVE_LIBCRYPTO_ECDSA], [1], [define to 1 if OpenSSL ecdsa support is available.])
  ])
])
