AC_DEFUN([DNSDIST_ENABLE_YAML], [
  AC_MSG_CHECKING([whether to enable YAML configuration])
  AC_ARG_ENABLE([yaml],
    AS_HELP_STRING([--enable-yaml], [enable YAML configuration (requires Rust and Cargo) @<:@default=no@:>@]),
    [enable_yaml=$enableval],
    [enable_yaml=no]
  )
  AC_MSG_RESULT([$enable_yaml])
  AM_CONDITIONAL([HAVE_YAML_CONFIGURATION], [test "x$enable_yaml" != "xno"])

  AM_COND_IF([HAVE_YAML_CONFIGURATION], [
    AC_DEFINE([HAVE_YAML_CONFIGURATION], [1], [Define to 1 if you enable YAML configuration support])
  ])
])
