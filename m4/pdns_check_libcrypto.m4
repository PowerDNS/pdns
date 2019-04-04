# SYNOPSIS
#
#   PDNS_CHECK_LIBCRYPTO([action-if-found[, action-if-not-found]])
#
# DESCRIPTION
#
#   Look for OpenSSL's libcrypto in a number of default spots, or in a
#   user-selected spot (via --with-libcrypto).  Sets
#
#     LIBCRYPTO_INCLUDES to the include directives required
#     LIBCRYPTO_LIBS to the -l directives required
#     LIBCRYPTO_LDFLAGS to the -L or -R flags required
#
#   and calls ACTION-IF-FOUND or ACTION-IF-NOT-FOUND appropriately
#
#   This macro sets LIBCRYPTO_INCLUDES such that source files should use the
#   openssl/ directory in include directives:
#
#     #include <openssl/hmac.h>
#
# LICENSE
#
# Taken and modified from AX_CHECK_OPENSSL by:
#   Copyright (c) 2009,2010 Zmanda Inc. <http://www.zmanda.com/>
#   Copyright (c) 2009,2010 Dustin J. Mitchell <dustin@zmanda.com>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 1

AU_ALIAS([CHECK_LIBCRYPTO], [PDNS_CHECK_LIBCRYPTO])
AC_DEFUN([PDNS_CHECK_LIBCRYPTO], [
    found=false
    AC_ARG_WITH([libcrypto],
        [AS_HELP_STRING([--with-libcrypto=DIR],
            [root of the OpenSSL directory])],
        [
            case "$withval" in
            "" | y | ye | yes | n | no)
            AC_MSG_ERROR([Invalid --with-libcrypto value])
              ;;
            *) ssldirs="$withval"
              ;;
            esac
        ], [
            # if pkg-config is installed and openssl has installed a .pc file,
            # then use that information and don't search ssldirs
            AC_CHECK_TOOL([PKG_CONFIG], [pkg-config])
            if test x"$PKG_CONFIG" != x""; then
                LIBCRYPTO_LDFLAGS=`$PKG_CONFIG libcrypto --libs-only-L 2>/dev/null`
                if test $? = 0; then
                    LIBCRYPTO_LIBS=`$PKG_CONFIG libcrypto --libs-only-l 2>/dev/null`
                    LIBCRYPTO_INCLUDES=`$PKG_CONFIG libcrypto --cflags-only-I 2>/dev/null`
                    ssldir=`$PKG_CONFIG libcrypto --variable=prefix 2>/dev/null`
                    found=true
                fi
            fi

            # no such luck; use some default ssldirs
            if ! $found; then
                ssldirs="/usr/local/ssl /usr/lib/ssl /usr/ssl /usr/pkg /usr/local /usr"
            fi
        ]
        )


    # note that we #include <openssl/foo.h>, so the OpenSSL headers have to be in
    # an 'openssl' subdirectory

    if ! $found; then
        LIBCRYPTO_INCLUDES=
        for ssldir in $ssldirs; do
            AC_MSG_CHECKING([for openssl/crypto.h in $ssldir])
            if test -f "$ssldir/include/openssl/crypto.h"; then
                LIBCRYPTO_INCLUDES="-I$ssldir/include"
                LIBCRYPTO_LDFLAGS="-L$ssldir/lib"
                LIBCRYPTO_LIBS="-lcrypto"
                found=true
                AC_MSG_RESULT([yes])
                break
            else
                AC_MSG_RESULT([no])
            fi
        done

        # if the file wasn't found, well, go ahead and try the link anyway -- maybe
        # it will just work!
    fi

    if $found; then
        AC_DEFINE([HAVE_LIBCRYPTO], [1], [Define to 1 if you have OpenSSL libcrypto])
    fi

    # try the preprocessor and linker with our new flags,
    # being careful not to pollute the global LIBS, LDFLAGS, and CPPFLAGS

    AC_MSG_CHECKING([whether compiling and linking against OpenSSL's libcrypto works])
    echo "Trying link with LIBCRYPTO_LDFLAGS=$LIBCRYPTO_LDFLAGS;" \
        "LIBCRYPTO_LIBS=$LIBCRYPTO_LIBS; LIBCRYPTO_INCLUDES=$LIBCRYPTO_INCLUDES" >&AS_MESSAGE_LOG_FD

    save_LIBS="$LIBS"
    save_LDFLAGS="$LDFLAGS"
    save_CPPFLAGS="$CPPFLAGS"
    LDFLAGS="$LDFLAGS $LIBCRYPTO_LDFLAGS"
    LIBS="$LIBCRYPTO_LIBS $LIBS"
    CPPFLAGS="$LIBCRYPTO_INCLUDES $CPPFLAGS"
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM([#include <openssl/crypto.h>], [ERR_load_CRYPTO_strings()])],
        [
            AC_MSG_RESULT([yes])
            AC_CHECK_FUNCS([RAND_bytes RAND_pseudo_bytes])
            $1
        ], [
            AC_MSG_RESULT([no])
            $2
        ])
    CPPFLAGS="$save_CPPFLAGS"
    LDFLAGS="$save_LDFLAGS"
    LIBS="$save_LIBS"

    AC_SUBST([LIBCRYPTO_INCLUDES])
    AC_SUBST([LIBCRYPTO_LIBS])
    AC_SUBST([LIBCRYPTO_LDFLAGS])
    AM_CONDITIONAL([HAVE_LIBCRYPTO], [test "x$LIBCRYPTO_LIBS" != "x"])
])
