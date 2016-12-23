AC_DEFUN([PDNS_ENABLE_MALLOC_TRACE], [
  AC_MSG_CHECKING([whether to enable code malloc-trace])
  AC_ARG_ENABLE([malloc-trace],
    AS_HELP_STRING([--enable-malloc-trace],
      [enable malloc-trace @<:@default=no@:>@]),
    [enable_malloc_trace=$enableval],
    [enable_malloc_trace=no]
  )
  AC_MSG_RESULT([$enable_malloc_trace])
  AM_CONDITIONAL([MALLOC_TRACE], [test "x$enable_malloc_trace" = "xyes"])  
  AS_IF([test "x$enable_malloc_trace" = "xyes"], 
  AC_DEFINE([MALLOC_TRACE], [1], [Define to 1 if you want to benefit from malloc trace]) )
])
