AC_DEFUN([PDNS_WITH_EBPF],[
  AC_MSG_CHECKING([if we have eBPF support])
  AC_ARG_WITH([ebpf],
    AS_HELP_STRING([--with-ebpf],[enable eBPF support @<:@default=auto@:>@]),
    [with_ebpf=$withval],
    [with_ebpf=auto],
  )
  AC_MSG_RESULT([$with_ebpf])

  AS_IF([test "x$with_ebpf" != "xno"], [
    AS_IF([test "x$with_ebpf" = "xyes" -o "x$with_ebpf" = "xauto"], [
      AC_CHECK_HEADERS([linux/bpf.h], bpf_headers=yes, bpf_headers=no)
    ])
  ])
  AS_IF([test "x$with_ebpf" = "xyes"], [
    AS_IF([test x"$bpf_headers" = "no"], [
      AC_MSG_ERROR([EBPF support requested but required eBPF headers were not found])
    ])
  ])
  AM_CONDITIONAL([HAVE_EBPF], [test x"$bpf_headers" = "xyes" ])
  AS_IF([test x"$bpf_headers" = "xyes" ],
    [AC_CHECK_DECL(BPF_FUNC_tail_call,
      [ AC_CHECK_DECL(SO_ATTACH_BPF,
        [ AC_DEFINE([HAVE_EBPF], [1], [Define if using eBPF.]) ],
        [ AS_IF([test "x$with_ebpf" = "xyes"], [
          AC_MSG_ERROR([EBPF support requested but SO_ATTACH_BPF not found])
        ])],
        [#include <sys/socket.h>
        ]
      )],
      [ AS_IF([test "x$with_ebpf" = "xyes"], [
        AC_MSG_ERROR([EBPF support requested but BPF_FUNC_tail_call not found in the eBPF headers])
      ])],
      [#include <linux/bpf.h>
      ]
    )]
  )
])
