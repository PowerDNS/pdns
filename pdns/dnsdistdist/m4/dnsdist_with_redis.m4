AC_DEFUN([DNSDIST_WITH_REDIS], [
  AC_MSG_CHECKING([whether we will we linking with libhiredis])
  HAVE_REDIS=0
  AC_ARG_WITH([redis],
    AS_HELP_STRING([--with-redis], [use Redis @<:@default=auto@:>@]),
    [with_redis=$withval],
    [with_redis=auto]
  )
  AC_MSG_RESULT([$with_redis])

  AS_IF([test "x$with_redis" != "xno"], [
    AS_IF([test "x$with_redis" = "xyes" -o "x$with_redis" = "xauto"], [
      PKG_CHECK_MODULES([REDIS], [libhiredis], [
        [HAVE_REDIS=1]
        AC_DEFINE([HAVE_REDIS], [1], [Define to 1 if you have REDIS])
        ],
        [AC_CHECK_HEADERS([hiredis/hiredis.h],
          [AC_CHECK_LIB([hiredis], [redisConnect],
            [
              REDIS_LIBS="-lhiredis"
              AC_DEFINE([HAVE_REDIS], [1], [Define to 1 if you have REDIS])
              [HAVE_REDIS=1]
            ],
            [:]
          )],
          [:]
        )]
      )
    ])
  ])
  AC_SUBST(REDIS_LIBS)
  AC_SUBST(REDIS_CFLAGS)
  AM_CONDITIONAL([HAVE_REDIS], [test "x$REDIS_LIBS" != "x"])
  AS_IF([test "x$with_redis" = "xyes"], [
    AS_IF([test x"$REDIS_LIBS" = "x"], [
      AC_MSG_ERROR([Redis requested but libraries were not found])
    ])
  ])
])
