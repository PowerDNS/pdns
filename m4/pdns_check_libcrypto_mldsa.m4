AC_DEFUN([PDNS_CHECK_LIBCRYPTO_MLDSA], [
  AC_REQUIRE([PDNS_CHECK_LIBCRYPTO])

  # Set the environment correctly for a possibly non-default OpenSSL path that was found by/supplied to PDNS_CHECK_LIBCRYPTO
  save_CPPFLAGS="$CPPFLAGS"
  save_LDFLAGS="$LDFLAGS"
  save_LIBS="$LIBS"

  CPPFLAGS="$LIBCRYPTO_INCLUDES $CPPFLAGS"
  LDFLAGS="$LIBCRYPTO_LDFLAGS $LDFLAGS"
  LIBS="$LIBCRYPTO_LIBS $LIBS"

  libcrypto_mldsa=no
  AC_CHECK_DECLS([NID_ML_DSA_44], [
    libcrypto_mldsa=yes
    AC_DEFINE([HAVE_LIBCRYPTO_ML_DSA_44], [1], [define to 1 if OpenSSL MLDSA support is available.])
  ], [ : ],
  [AC_INCLUDES_DEFAULT
  #include <$sslincdir/openssl/evp.h>])

  AS_IF([test "$libcrypto_mldsa" = "yes" ], [
    AC_DEFINE([HAVE_LIBCRYPTO_MLDSA], [1], [define to 1 if OpenSSL MLDSA support is available.])
  ], [ : ])

  # Restore variables
  CPPFLAGS="$save_CPPFLAGS"
  LDFLAGS="$save_LDFLAGS"
  LIBS="$save_LIBS"
])
