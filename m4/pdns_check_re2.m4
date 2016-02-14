AC_DEFUN([PDNS_CHECK_RE2], [
    PKG_CHECK_MODULES([RE2], [re2], [HAVE_RE2=1], [HAVE_RE2=0])
    AM_CONDITIONAL([HAVE_RE2], [test "$HAVE_RE2" -eq 1])
    AS_IF([test "$HAVE_RE2" -eq 1], [AC_DEFINE([HAVE_RE2], [1], [Define if using RE2.])])
    
])
