AC_DEFUN([DNSDIST_CHECK_RAGEL], [
  AC_CHECK_PROG([RAGEL], [ragel], [ragel])
  if test "x$RAGEL" = "x"; then
    if test ! -f "${srcdir}/dnslabeltext.cc"; then
      AC_MSG_ERROR([ragel is missing and you don't have ${srcdir}/dnslabeltext.cc. Install ragel or download sources from www.dnsdist.org])
    fi
  fi
])
