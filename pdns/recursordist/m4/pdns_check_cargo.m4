AC_DEFUN([PDNS_CHECK_CARGO], [
  AC_REQUIRE([AC_PROG_SED])

  AC_CHECK_PROG(CARGO, [cargo], [cargo], $CARGO)
  AS_IF(test x$CARGO = x,
    AC_MSG_ERROR([cargo is required])
  )
  minimum=$1
  cargo_version=`$CARGO --version | $SED -e 's/^cargo //g'`
  AX_COMPARE_VERSION([$cargo_version],[lt],[$minimum], [
    AC_MSG_ERROR([need at least cargo version $minimum])
  ])
])
