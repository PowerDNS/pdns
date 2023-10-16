AC_DEFUN([PDNS_WITH_LIBH2OEVLOOP], [
  AC_MSG_CHECKING([whether we will be linking in libh2o-evloop])
  HAVE_LIBH2OEVLOOP=0
  AC_ARG_WITH([h2o],
    AS_HELP_STRING([--with-h2o],[use libh2o-evloop @<:@default=no@:>@]),
    [with_h2o=$withval],
    [with_h2o=no],
  )
  AC_MSG_RESULT([$with_h2o])

  AS_IF([test "x$with_h2o" = "xyes" -o "x$with_h2o" = "xauto"], [
    PKG_CHECK_MODULES([LIBH2OEVLOOP], [libh2o-evloop], [
      [HAVE_LIBH2OEVLOOP=1]
      AC_DEFINE([HAVE_LIBH2OEVLOOP], [1], [Define to 1 if you have libh2o-evloop])
      save_CFLAGS=$CFLAGS
      save_LIBS=$LIBS
      CFLAGS="$LIBH2OEVLOOP_CFLAGS $CFLAGS"
      LIBS="$LIBH2OEVLOOP_LIBS $LIBS"
      AC_CHECK_DECLS([h2o_socket_get_ssl_server_name], [
          AC_DEFINE([HAVE_H2O_SOCKET_GET_SSL_SERVER_NAME], [1], [define to 1 if h2o_socket_get_ssl_server_name is available.])
        ],
        [ : ],
        [AC_INCLUDES_DEFAULT
          #include <h2o/socket.h>
      ])
      CFLAGS=$save_CFLAGS
      LIBS=$save_LIBS
    ], [ : ])
  ])
  AM_CONDITIONAL([HAVE_LIBH2OEVLOOP], [test "x$LIBH2OEVLOOP_LIBS" != "x"])
  AM_COND_IF([HAVE_LIBH2OEVLOOP], [
    AC_DEFINE([HAVE_LIBH2OEVLOOP], [1], [Define to 1 if you enable h2o-evloop support])
  ])

  AS_IF([test "x$with_h2o" = "xyes"], [
    AS_IF([test x"LIBH2OEVLOOP_LIBS" = "x"], [
      AC_MSG_ERROR([h2o-evloop requested but libraries were not found])
    ])
  ])
])
