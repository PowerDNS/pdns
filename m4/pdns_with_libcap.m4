AC_DEFUN([PDNS_WITH_LIBCAP], [
  AC_MSG_CHECKING([whether we will be linking in libcap])
  HAVE_LIBCAPS=0
  AC_ARG_WITH([libcap],
    AS_HELP_STRING([--with-libcap],[use libcap @<:@default=auto@:>@]),
    [with_libcap=$withval],
    [with_libcap=auto],
  )
  AC_MSG_RESULT([$with_libcap])

  AS_IF([test "x$with_libcap" != "xno"], [
    AS_IF([test "x$with_libcap" = "xyes" -o "x$with_libcap" = "xauto"], [
      PKG_CHECK_MODULES([LIBCAP], [libcap] , [
        [HAVE_LIBCAP=1]
        AC_DEFINE([HAVE_LIBCAP], [1], [Define to 1 if you have libcap])
      ], [ : ])
    ])
  ])
  AM_CONDITIONAL([HAVE_LIBCAP], [test "x$LIBCAP_LIBS" != "x"])
  AS_IF([test "x$with_libcap" = "xyes"], [
    AS_IF([test x"$LIBCAP_LIBS" = "x"], [
      AC_MSG_ERROR([libcap requested but libraries were not found])
    ])
  ])
])
