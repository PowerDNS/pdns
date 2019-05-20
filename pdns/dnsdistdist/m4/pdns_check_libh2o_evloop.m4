AC_DEFUN([PDNS_CHECK_LIBH2OEVLOOP], [
  HAVE_LIBH2OEVLOOP=0
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
  AM_CONDITIONAL([HAVE_LIBH2OEVLOOP], [test "x$LIBH2OEVLOOP_LIBS" != "x"])
])
