AC_DEFUN([PDNS_CHECK_CURL], [
  AC_CHECK_PROG([CURL], [curl], [curl])
  if test "x$CURL" = "x"; then
    if test ! -f "${srcdir}/effective_tld_names.dat"; then
      AC_MSG_ERROR([curl is missing and you don't have ${srcdir}//effective_tld_names.dat. Install curl or download sources from www.powerdns.com])
    fi
  fi
])

