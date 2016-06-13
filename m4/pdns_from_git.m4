AC_DEFUN([PDNS_FROM_GIT], [
  AM_CONDITIONAL([FROM_GIT], [test -d "$srcdir/.git"])
])
