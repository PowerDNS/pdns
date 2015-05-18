AC_DEFUN([PDNS_WITH_SYSTEM_POLARSSL],[
  AC_ARG_WITH([system-polarssl],
    [AS_HELP_STRING([--with-system-polarssl], [use system PolarSSL @<:@default=no@:>@])],
    [],
    [with_system_polarssl=no],
  )

  POLARSSL_SUBDIR=polarssl
  POLARSSL_CFLAGS=-I\$\(top_srcdir\)/pdns/ext/$POLARSSL_SUBDIR/include/
  POLARSSL_LIBS="-L\$(top_builddir)/pdns/ext/$POLARSSL_SUBDIR/library/ -lpolarssl"

  AS_IF([test "x$with_system_polarssl" = "xyes"],[
    OLD_LIBS=$LIBS
    LIBS=""
    AC_SEARCH_LIBS([sha1_hmac], [mbedtls polarssl],[
      POLARSSL_LIBS=$LIBS
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
        [have_system_polarssl=yes],
        [have_system_polarssl=no]
      )
      AC_MSG_RESULT([$have_system_polarssl])
      ],
      [have_system_polarssl=no]
    )
    LIBS=$OLD_LIBS
    ],
    [have_system_polarssl=no]
  )

  AS_IF([test "x$have_system_polarssl" = "xyes"],[
    POLARSSL_CFLAGS=
    POLARSSL_SUBDIR=
    ],[
    AS_IF([test "x$with_system_polarssl" = "xyes"],[
      AC_MSG_ERROR([use of system polarssl requested but not found])]
    )]
  )

  AC_SUBST(POLARSSL_CFLAGS)
  AC_SUBST(POLARSSL_LIBS)
  AC_SUBST(POLARSSL_SUBDIR)
]
)

