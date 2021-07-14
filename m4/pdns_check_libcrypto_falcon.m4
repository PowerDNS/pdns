AC_DEFUN([PDNS_CHECK_LIBCRYPTO_FALCON], [
  AC_REQUIRE([PDNS_CHECK_LIBCRYPTO])

  libcrypto_falcon=yes
  AC_DEFINE([HAVE_LIBCRYPTO_FALCON], [1], [define to 1 if OpenSSL falcon support is available.])

  LIBCRYPTO_LIBS="-loqs $LIBCRYPTO_LIBS"
  LIBS="$LIBCRYPTO_LIBS $LIBS"
])
