AC_DEFUN([PDNS_WITH_QUICHE], [
  AC_MSG_CHECKING([whether we will be linking in quiche])
  HAVE_QUICHE=0
  AC_ARG_WITH([quiche],
    AS_HELP_STRING([--with-quiche],[use quiche @<:@default=auto@:>@]),
    [with_quiche=$withval],
    [with_quiche=auto],
  )
  AC_MSG_RESULT([$with_quiche])

  AS_IF([test "x$with_quiche" != "xno"], [
    AS_IF([test "x$with_quiche" = "xyes" -o "x$with_quiche" = "xauto"], [
      PKG_CHECK_MODULES([QUICHE], [quiche >= 0.23.0], [
        [HAVE_QUICHE=1]
        AC_DEFINE([HAVE_QUICHE], [1], [Define to 1 if you have quiche])
        AC_DEFINE([HAVE_QUICHE_H3_EVENT_HEADERS_HAS_MORE_FRAMES], [1], [Define to 1 if the Quiche API has quiche_h3_event_headers_has_more_frames instead of quiche_h3_event_headers_has_body])
        AC_DEFINE([HAVE_QUICHE_STREAM_ERROR_CODES], [1], [Define to 1 if the Quiche API includes error code in quiche_conn_stream_recv and quiche_conn_stream_send])
      ], [
        PKG_CHECK_MODULES([QUICHE], [quiche >= 0.22.0], [
          [HAVE_QUICHE=1]
          AC_DEFINE([HAVE_QUICHE], [1], [Define to 1 if you have quiche])
          AC_DEFINE([HAVE_QUICHE_STREAM_ERROR_CODES], [1], [Define to 1 if the Quiche API includes error code in quiche_conn_stream_recv and quiche_conn_stream_send])
        ], [
          # Quiche is older than 0.22.0, or no Quiche at all
          PKG_CHECK_MODULES([QUICHE], [quiche >= 0.15.0], [
            [HAVE_QUICHE=1]
            AC_DEFINE([HAVE_QUICHE], [1], [Define to 1 if you have quiche])
          ], [ : ])
        ])
      ])
    ])
  ])
  AM_CONDITIONAL([HAVE_QUICHE], [test "x$QUICHE_LIBS" != "x"])
  AS_IF([test "x$with_quiche" = "xyes"], [
    AS_IF([test x"$QUICHE_LIBS" = "x"], [
      AC_MSG_ERROR([quiche requested but libraries were not found])
    ])
  ])
])
