AC_DEFUN([PDNS_CHECK_LIBCRYPTO_EDDSA], [
  AC_REQUIRE([PDNS_CHECK_LIBCRYPTO])

  # Set the environment correctly for a possibly non-default OpenSSL path that was found by/supplied to PDNS_CHECK_LIBCRYPTO
  save_CPPFLAGS="$CPPFLAGS"
  save_LDFLAGS="$LDFLAGS"
  save_LIBS="$LIBS"

  CPPFLAGS="$LIBCRYPTO_INCLUDES $CPPFLAGS"
  LDFLAGS="$LIBCRYPTO_LDFLAGS $LDFLAGS"
  LIBS="$LIBCRYPTO_LIBS $LIBS"

  libcrypto_ed25519=no
  libcrypto_ed448=no
  AC_CHECK_DECLS([NID_ED25519], [
    libcrypto_ed25519=yes
    AC_DEFINE([HAVE_LIBCRYPTO_ED25519], [1], [define to 1 if OpenSSL ed25519 support is available.])
  ], [ : ],
  [AC_INCLUDES_DEFAULT
  #include <$ssldir/include/openssl/evp.h>])
  AC_CHECK_DECLS([NID_ED448], [
    libcrypto_ed448=yes
    AC_DEFINE([HAVE_LIBCRYPTO_ED448], [1], [define to 1 if OpenSSL ed448 support is available.])
  ], [ : ],
  [AC_INCLUDES_DEFAULT
  #include <$ssldir/include/openssl/evp.h>])

  AS_IF([test "$libcrypto_ed25519" = "yes" -o "$libcrypto_ed448" = "yes"], [
    AC_DEFINE([HAVE_LIBCRYPTO_EDDSA], [1], [define to 1 if OpenSSL EDDSA support is available.])
  ], [ : ])

  # Restore variables
  CPPFLAGS="$save_CPPFLAGS"
  LDFLAGS="$save_LDFLAGS"
  LIBS="$save_LIBS"
])
