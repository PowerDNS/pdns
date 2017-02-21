AC_DEFUN([PDNS_WITH_NET_SNMP], [
  AC_MSG_CHECKING([if we need to link in Net SNMP])
  AC_ARG_WITH([net-snmp],
    AS_HELP_STRING([--with-net-snmp],[enable net snmp support @<:@default=auto@:>@]),
    [with_net_snmp=$withval],
    [with_net_snmp=auto],
  )
  AC_MSG_RESULT([$with_net_snmp])

  AS_IF([test "x$with_net_snmp" != "xno"], [
    AS_IF([test "x$with_net_snmp" = "xyes" -o "x$with_net_snmp" = "xauto"], [
      AC_CHECK_PROG([NET_SNMP_CFLAGS], [net-snmp-config], [`net-snmp-config --cflags`])
      AC_CHECK_PROG([NET_SNMP_LIBS], [net-snmp-config], [`net-snmp-config --agent-libs`])
    ])
  ])
  AS_IF([test "x$with_net_snmp" = "xyes"], [
    AS_IF([test x"$NET_SNMP_LIBS" = "x"], [
      AC_MSG_ERROR([Net SNMP requested but libraries were not found])
    ])
  ])
  AM_CONDITIONAL([HAVE_NET_SNMP], [test x"$NET_SNMP_LIBS" != "x"])
  AS_IF([test x"$NET_SNMP_LIBS" != "x"], [AC_DEFINE([HAVE_NET_SNMP], [1], [Define if using Net SNMP.])])
])
