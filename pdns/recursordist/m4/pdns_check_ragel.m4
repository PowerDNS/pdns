AC_DEFUN([PDNS_CHECK_RAGEL], [
  AC_CHECK_PROG([RAGEL], [ragel], [ragel])
  if test "x$RAGEL" = "x"; then
    if test ! -f "${srcdir}/dnslabeltext.cc"; then
      AC_MSG_ERROR([ragel is missing and you don't have ${srcdir}/dnslabeltext.cc. Install ragel or download sources from www.powerdns.com])
    fi
  fi
])
