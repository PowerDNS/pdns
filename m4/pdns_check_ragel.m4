AC_DEFUN([PDNS_CHECK_RAGEL], [
  AC_CHECK_PROG([RAGEL], [ragel], [ragel])
  if test "x$RAGEL" = "x"; then
    if test ! -f "${srcdir}/$1"; then
      AC_MSG_ERROR([ragel is missing and you don't have ${srcdir}/$1. Install ragel or download sources from $2])
    fi
  fi
])
