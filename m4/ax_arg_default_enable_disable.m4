AC_DEFUN([AX_ARG_DEFAULT_ENABLE], [
AC_ARG_ENABLE([$1], AS_HELP_STRING([--disable-$1], [$2 (default is ENABLED)]))
AX_PARSE_VALUE([$1], [y])
])

AC_DEFUN([AX_ARG_DEFAULT_DISABLE], [
AC_ARG_ENABLE([$1], AS_HELP_STRING([--enable-$1], [$2 (default is DISABLED)]))
AX_PARSE_VALUE([$1], [n])
])

dnl This function should not be called outside of this file
AC_DEFUN([AX_PARSE_VALUE], [
AS_IF([test "x$enable_$1" = "xno"], [
    ax_cv_$1="n"
], [test "x$enable_$1" = "xyes"], [
    ax_cv_$1="y"
], [test -z $ax_cv_$1], [
    ax_cv_$1="$2"
])
$1=$ax_cv_$1
AC_SUBST($1)])
