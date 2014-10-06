AC_DEFUN([PDNS_CHECK_POLARSSL],[
    AC_CHECK_LIB([polarssl], [sha1_hmac],[
        AC_MSG_CHECKING([for PolarSSL version >= 1.1])
        AC_COMPILE_IFELSE([
            AC_LANG_PROGRAM(
                [[#include <polarssl/version.h>]],
                [[
                    #if POLARSSL_VERSION_NUMBER < 0x01010000
                        #error invalid version
                    #endif
                ]]
            )],
            [have_polarssl=yes],
            [have_polarssl=no]
        )
        AC_MSG_RESULT([$have_polarssl])
        ],
        [have_polarssl=no]
    )

    AS_IF([test "x$have_polarssl" = "xyes"],
        [POLARSSL_LIBS=-lpolarssl],
        [AC_MSG_ERROR([PolarSSL not found])]
    )
    AC_SUBST(POLARSSL_LIBS)
])

