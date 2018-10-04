AC_DEFUN([PDNS_WITH_LIBDECAF],[
  AC_MSG_CHECKING([whether we will be linking in libdecaf])
  AC_ARG_WITH([libdecaf],
    [AS_HELP_STRING([--with-libdecaf],[use libdecaf  @<:@default=no@:>@])],
    [with_libdecaf=$withval],
    [with_libdecaf=no]
  )
  AC_MSG_RESULT([$with_libdecaf])

  AM_CONDITIONAL([LIBDECAF],[test "x$with_libdecaf" != "xno"])

  AS_IF([test "x$with_libdecaf" != "xno"],[
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
