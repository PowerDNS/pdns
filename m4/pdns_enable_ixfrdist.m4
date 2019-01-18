AC_DEFUN([PDNS_ENABLE_IXFRDIST], [
  AC_MSG_CHECKING([whether we will be building ixfrdist])
  AC_ARG_ENABLE([ixfrdist],
    [AS_HELP_STRING([--enable-ixfrdist], [if we should build and install ixfrdist @<:@default=no@:>@])
  ], [
    enable_ixfrdist=$enableval
  ], [
    enable_ixfrdist=no
  ])

  AC_MSG_RESULT([$enable_ixfrdist])
  AM_CONDITIONAL([IXFRDIST], [test "x$enable_ixfrdist" != "xno"])
  AS_IF([test "x$enable_ixfrdist" != "xno"], [
    PKG_CHECK_MODULES([YAML], [yaml-cpp >= 0.5], [ : ], [
      AC_MSG_ERROR([Could not find yaml-cpp >= 0.5, required for ixfrdist])
    ])
  ])
])
