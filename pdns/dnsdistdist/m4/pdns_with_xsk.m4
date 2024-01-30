AC_DEFUN([PDNS_WITH_XSK],[
  AC_MSG_CHECKING([if we have AF_XDP (XSK) support])
  AC_ARG_WITH([xsk],
    AS_HELP_STRING([--with-xsk],[enable AF_XDP (XDK) support @<:@default=auto@:>@]),
    [with_xsk=$withval],
    [with_xsk=auto],
  )
  AC_MSG_RESULT([$with_xsk])

  AS_IF([test "x$with_xsk" != "xno"], [
    AS_IF([test "x$with_xsk" = "xyes" -o "x$with_xsk" = "xauto"], [
      PKG_CHECK_MODULES([XDP], [libxdp], [
        AC_DEFINE([HAVE_XDP], [1], [Define to 1 if you have the XDP library])
      ], [:])
      PKG_CHECK_MODULES([BPF], [libbpf], [
        AC_DEFINE([HAVE_BPF], [1], [Define to 1 if you have the BPF library])
        save_CFLAGS=$CFLAGS
        save_LIBS=$LIBS
        CFLAGS="$BPF_CFLAGS $CFLAGS"
        LIBS="$BPF_LIBS $LIBS"
        AC_CHECK_FUNCS([bpf_xdp_query])
        CFLAGS=$save_CFLAGS
        LIBS=$save_LIBS
      ], [:])
    ])
  ])

  AM_CONDITIONAL([HAVE_XSK], [test x"$BPF_LIBS" != "x" -a x"$XDP_LIBS" != "x"])
  AM_COND_IF([HAVE_XSK], [
    AC_DEFINE([HAVE_XSK], [1], [Define to 1 if you have AF_XDP (XSK) support enabled])
  ])

  AS_IF([test "x$with_xsk" = "xyes"], [
    AS_IF([test x"$BPF_LIBS" = "x" -o x"$XDP_LIBS" = "x" ], [
      AC_MSG_ERROR([AF_XDP (XSK) support requested but required libbpf and/or libxdp were not found])
    ])
  ])
])
