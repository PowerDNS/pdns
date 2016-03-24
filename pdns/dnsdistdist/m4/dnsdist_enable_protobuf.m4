AC_DEFUN([DNSDIST_ENABLE_PROTOBUF], [
  AC_MSG_CHECKING([whether to enable protobuf support])
  AC_ARG_ENABLE([protobuf],
    AS_HELP_STRING([--enable-protobuf],[enable protobuf support @<:@default=no@:>@]),
    [enable_protobuf=$enableval],
    [enable_protobuf=no],
  )
  AC_MSG_RESULT([$enable_protobuf])
  AS_IF([test "x$enable_protobuf" = "xyes"], [
    PKG_CHECK_MODULES([PROTOBUF], [protobuf], [HAVE_PROTOBUF=1], [AC_MSG_ERROR([Could not find protobuf])])
  ], [HAVE_PROTOBUF=0])
  AM_CONDITIONAL([HAVE_PROTOBUF], [test "$HAVE_PROTOBUF" -eq 1])
  AS_IF([test "$HAVE_PROTOBUF" -eq 1], [AC_DEFINE([HAVE_PROTOBUF], [1], [Define if using protobuf.])])
])
