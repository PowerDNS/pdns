AC_DEFUN([PDNS_CHECK_LINKCHECKER], [
  AC_CHECK_PROG([LINKCHECKER], [linkchecker], [linkchecker], [no])

  AS_IF([test "x$LINKCHECKER" = "xno"], [
      AC_MSG_WARN([linkchecker is missing, unable to verify links in the documentation.])
    ])
  AM_CONDITIONAL([HAVE_LINKCHECKER], [test "x$LINKCHECKER" != "xno"])
])

