AC_DEFUN([PDNS_CHECK_LIBCRYPTO_FALCON], [
  AC_REQUIRE([PDNS_CHECK_LIBCRYPTO])
  # Set the environment correctly for a possibly non-default OpenSSL path that was found by/supplied to PDNS_CHECK_LIBCRYPTO
  save_CPPFLAGS="$CPPFLAGS"
  save_LDFLAGS="$LDFLAGS"
  save_LIBS="$LIBS"
  CPPFLAGS="$LIBCRYPTO_INCLUDES $CPPFLAGS"
  LDFLAGS="$LIBCRYPTO_LDFLAGS $LDFLAGS"
  LIBS="$LIBCRYPTO_LIBS $LIBS"
  libcrypto_falcon=no

  AC_CHECK_DECLS([NID_falcon512], [
    libcrypto_falcon=yes
    AC_DEFINE([HAVE_LIBCRYPTO_FALCON], [1], [define to 1 if OpenSSL Falcon512 support is available.])
  ], [ : ],
  [AC_INCLUDES_DEFAULT
  #include <$ssldir/include/openssl/evp.h>])
  
  # Restore variables
  CPPFLAGS="$save_CPPFLAGS"
  LDFLAGS="$save_LDFLAGS"
  LIBS="$save_LIBS"
])