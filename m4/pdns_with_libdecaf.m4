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

    AS_IF([test "x$LIBDECAF_CFLAGS" = "x"],[
      AC_MSG_CHECKING([for libdecaf headers])
      libdecaf_header_dir=""

      header_dirs="/usr /usr/local"
      for header_dir in $header_dirs; do
        if test -f "$header_dir/include/decaf.hxx"; then
          libdecaf_header_dir="$header_dir/include"
          break
        fi

        if test -f "$header_dir/include/decaf/decaf.hxx"; then
          libdecaf_header_dir="$header_dir/include/decaf"
          break
        fi
      done

      AS_IF([test "x$libdecaf_header_dir" != "x"],[
          AC_MSG_RESULT([$libdecaf_header_dir])
          LIBDECAF_CFLAGS="-I$libdecaf_header_dir"
        ],
        [AC_MSG_RESULT([not found])])
    ])

    AC_SUBST([LIBDECAF_CFLAGS])

    save_CXXFLAGS="$CXXFLAGS"
    CXXFLAGS="$CXXFLAGS $LIBDECAF_CFLAGS"
    AC_CHECK_HEADERS(
      [decaf.hxx],
      [],
      [AC_MSG_ERROR([cannot find libdecaf headers])]
    )
    CXXFLAGS="$save_CXXFLAGS"
  ])
])
