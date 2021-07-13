AC_DEFUN([PDNS_ENABLE_REMOTEBACKEND_ZEROMQ],[
  AC_MSG_CHECKING([whether to enable ZeroMQ connector in remotebackend])
  AC_ARG_ENABLE([remotebackend_zeromq],
    AS_HELP_STRING([--enable-remotebackend-zeromq],
      [enable ZeroMQ connector for remotebackend @<:@default=no@:>@]
    ),
    [enable_remotebackend_zeromq=$enableval],
    [enable_remotebackend_zeromq=no]
  )

  AC_MSG_RESULT([$enable_remotebackend_zeromq])

  AM_CONDITIONAL([REMOTEBACKEND_ZEROMQ],[test "x$enable_remotebackend_zeromq" != "xno"])
  AC_SUBST(REMOTEBACKEND_ZEROMQ)

  AS_IF([test "x$enable_remotebackend_zeromq" != "xno"],
    [
      AS_IF([test "x$have_remotebackend" = "xyes"],
        [
          PKG_CHECK_MODULES([LIBZMQ], [libzmq],
            [
              AC_DEFINE([HAVE_LIBZMQ], [1], [Define to 1 if you have libzmq])
              AC_DEFINE([REMOTEBACKEND_ZEROMQ], [1], [Define to 1 if you have the ZeroMQ connector])
              REMOTEBACKEND_ZEROMQ=yes
            ],
            [AC_MSG_ERROR([Could not find libzmq])]
          )

          old_CXXFLAGS="$CXXFLAGS"
          old_LDFLAGS="$LDFLAGS"
          CXXFLAGS="$CFLAGS $LIBZMQ_CFLAGS"
          LDFLAGS="$LDFLAGS $LIBZMQ_LIBS"
          AC_CHECK_LIB([zmq], [zmq_msg_send],
            [
              AC_DEFINE([HAVE_ZMQ_MSG_SEND], [1], [Define to 1 if the ZeroMQ 3.x or greater API is available])
            ]
          )
          CXXFLAGS="$old_CXXFLAGS"
          LDFLAGS="$old_LDFLAGS"
        ],
        [AC_MSG_ERROR([remotebackend "zeromq" selected but the "remote" backend itself is not selected. Please add "remote" to your modules or dynmodules list and re-run configure!])]
      )
    ]
  )
])
