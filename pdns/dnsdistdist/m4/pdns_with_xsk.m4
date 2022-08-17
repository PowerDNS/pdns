AC_DEFUN([PDNS_WITH_XSK],[
  AC_MSG_CHECKING([if we have xsk support])
  AC_ARG_WITH([xsk],
    AS_HELP_STRING([--with-xsk],[enable xsk support @<:@default=auto@:>@]),
    [with_xsk=$withval],
    [with_xsk=auto],
  )
  AC_MSG_RESULT([$with_xsk])

  AS_IF([test "x$with_xsk" != "xno"], [
    AS_IF([test "x$with_xsk" = "xyes" -o "x$with_xsk" = "xauto"], [
      AC_CHECK_HEADERS([xdp/xsk.h], xsk_headers=yes, xsk_headers=no)
    ])
  ])
  AS_IF([test "x$with_xsk" = "xyes"], [
    AS_IF([test x"$xsk_headers" = "no"], [
      AC_MSG_ERROR([XSK support requested but required libxdp were not found])
    ])
  ])
  AS_IF([test x"$xsk_headers" = "xyes" ], [ AC_DEFINE([HAVE_XSK], [1], [Define if using eBPF.]) ])
  AM_CONDITIONAL([HAVE_XSK], [test x"$xsk_headers" = "xyes" ])
])
