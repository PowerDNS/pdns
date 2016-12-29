AC_DEFUN([PDNS_CHECK_LIBCRYPTO_ECDSA], [
  AC_REQUIRE([PDNS_CHECK_LIBCRYPTO])

  # Set the environment correctly for a possibly non-default OpenSSL path that was found by/supplied to PDNS_CHECK_LIBCRYPTO
  save_CPPFLAGS="$CPPFLAGS"
  save_LDFLAGS="$LDFLAGS"
  save_LIBS="$LIBS"

  CPPFLAGS="$LIBCRYPTO_INCLUDES $CPPFLAGS"
  LDFLAGS="$LIBCRYPTO_LDFLAGS $LDFLAGS"
  LIBS="$LIBCRYPTO_LIBS $LIBS"

  # Find the headers we need for ECDSA
  libcrypto_ecdsa=yes
  AC_CHECK_HEADER([$ssldir/include/openssl/ecdsa.h], [
    AC_CHECK_DECLS([NID_X9_62_prime256v1, NID_secp384r1], [ : ], [
      libcrypto_ecdsa=no
    ], [AC_INCLUDES_DEFAULT
#include <$ssldir/include/openssl/evp.h>
    ])
  ], [
    libcrypto_ecdsa=no
  ])

  AS_IF([test "x$libcrypto_ecdsa" = "xyes"], [
    AC_DEFINE([HAVE_LIBCRYPTO_ECDSA], [1], [define to 1 if OpenSSL ecdsa support is available.])
  ])

  # Restore variables
  CPPFLAGS="$save_CPPFLAGS"
  LDFLAGS="$save_LDFLAGS"
  LIBS="$save_LIBS"
])
