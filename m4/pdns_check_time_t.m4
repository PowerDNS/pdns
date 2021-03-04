AC_DEFUN([PDNS_CHECK_TIME_T], [
AX_COMPILE_CHECK_SIZEOF(time_t)
AS_IF([test $ac_size -lt 8], [AC_MSG_ERROR([size of time_t is $ac_size, which is not large enough to fix the y2k38 bug])])
AX_CHECK_SIGN([time_t], [:], [AC_MSG_ERROR([time_t is unsigned, PowerDNS code relies on it being signed])], [
  #include <sys/types.h>
])
])
