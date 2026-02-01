AC_DEFUN([PDNS_ENABLE_IPCRYPT2], [
  AC_MSG_CHECKING([whether to enable ipcrypt2 support])
  AC_ARG_ENABLE([ipcrypt2],
    AS_HELP_STRING([--enable-ipcrypt2], [enable ipcrypt2 support @<:@default=yes@:>@]),
    [enable_ipcrypt2=$enableval],
    [enable_ipcrypt2=yes]
  )
  AC_MSG_RESULT([$enable_ipcrypt2])

  AM_CONDITIONAL([HAVE_IPCRYPT2], [test "x$enable_ipcrypt2" != "xno"])
  AM_COND_IF([HAVE_IPCRYPT2], [
    AC_DEFINE([HAVE_IPCRYPT2], [1], [Define to 1 if you enable ipcrypt2 support])
  ])
])
