AC_DEFUN([PDNS_CHECK_CURL_PROGRAM], [
  AC_CHECK_PROG([CURL], [curl], [curl], [no])

  AS_IF([test "x$CURL" = "xno"], [
    AC_MSG_ERROR([curl program is missing, required for running remotebackend unit tests])
  ])
])
