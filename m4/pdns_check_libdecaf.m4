AC_DEFUN([PDNS_CHECK_LIBDECAF],[
  AC_MSG_CHECKING([whether we will be linking in libdecaf])
  AC_ARG_ENABLE([libdecaf],
    [AS_HELP_STRING([--enable-libdecaf],[use libdecaf  @<:@default=no@:>@])],
    [enable_libdecaf=$enableval],
    [enable_libdecaf=no]
  )
  AC_MSG_RESULT([$enable_libdecaf])

  AM_CONDITIONAL([LIBDECAF],[test "x$enable_libdecaf" != "xno"])

  AS_IF([test "x$enable_libdecaf" != "xno"],[
    save_LIBS=$LIBS
    LIBS=""
    AC_SEARCH_LIBS([decaf_ed25519_sign],[decaf],[
      AC_DEFINE([HAVE_LIBDECAF],[1],[Define to 1 if you have libdecaf])
      AC_SUBST([LIBDECAF_LIBS],["$LIBS"])
    ],[
        AC_MSG_ERROR([Could not find libdecaf])
    ])
    LIBS="$save_LIBS"
  ])
])
