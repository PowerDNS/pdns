AC_DEFUN([PDNS_ENABLE_TOOLS], [
  AC_REQUIRE([PDNS_CHECK_LIBCURL]) dnl We only care about the #define HAVE_LIBCURL and can build tools without DOH support.
  AC_MSG_CHECKING([whether we will be building and installing the extra tools])
  AC_ARG_ENABLE([tools],
    [AS_HELP_STRING([--enable-tools], [if we should build and install the tools @<:@default=no@:>@])],
    [enable_tools=$enableval],
    [enable_tools=no]
    )
  AC_MSG_RESULT([$enable_tools])

  AM_CONDITIONAL([TOOLS], [test "x$enable_tools" != "xno"])
])
