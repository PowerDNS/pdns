AC_DEFUN([PDNS_WITH_PROTOBUF], [
  AC_MSG_CHECKING([if we need to link in protobuf])
  AC_ARG_WITH([protobuf],
    AS_HELP_STRING([--with-protobuf],[enable protobuf support @<:@default=auto@:>@]),
    [with_protobuf=$withval],
    [with_protobuf=auto],
  )
  AC_MSG_RESULT([$with_protobuf])

  AS_IF([test "x$with_protobuf" != "xno"], [
    AS_IF([test "x$with_protobuf" = "xyes" -o "x$with_protobuf" = "xauto"], [
      PKG_CHECK_MODULES([PROTOBUF], [protobuf], [ : ], [ : ])
      AC_CHECK_PROG([PROTOC], [protoc], [protoc])
    ])
  ])
  AS_IF([test "x$with_protobuf" = "xyes"], [
    AS_IF([test x"$PROTOBUF_LIBS" = "x"], [
      AC_MSG_ERROR([Protobuf requested but libraries were not found])
    ])
    AS_IF([test x"$PROTOC" = "x"], [
      AC_MSG_ERROR([Protobuf requested but the protobuf compiler was not found])
    ])
  ])
  AM_CONDITIONAL([HAVE_PROTOBUF], [test x"$PROTOBUF_LIBS" != "x"])
  AM_CONDITIONAL([HAVE_PROTOC], [test x"$PROTOC" != "x"])
  AS_IF([test x"$PROTOBUF_LIBS" != "x"], [AC_DEFINE([HAVE_PROTOBUF], [1], [Define if using protobuf.])])
])
