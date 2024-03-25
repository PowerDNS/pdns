AC_DEFUN([PDNS_CHECK_TIME_T], [
AC_ARG_ENABLE([experimental_64bit_time_t_support_on_glibc],
  AS_HELP_STRING([--enable-experimental-64bit-time_t-support-on-glibc],
    [enable experimental 64bit time_t support on >=glibc-2.34 for 32bit systems @<:@default=no@:>@]
  ),
  [enable_experimental_64bit_time_t_support_on_glibc=$enableval],
  [enable_experimental_64bit_time_t_support_on_glibc=no]
)
AS_IF([test "x$enable_experimental_64bit_time_t_support_on_glibc" != "xno"],
  # _TIME_BITS=64 is supported on glibc-2.34 and requires _FILE_OFFSET_BITS=64
  [AC_EGREP_CPP(yes, [
    #include <features.h>
    #if __GLIBC__ == 2 && __GLIBC_MINOR__ >= 34 || __GLIBC__ > 2
      yes
    #endif
    ], [
    CFLAGS="${CFLAGS} -D_FILE_OFFSET_BITS=64 -D_TIME_BITS=64"
    CXXFLAGS="${CXXFLAGS} -D_FILE_OFFSET_BITS=64 -D_TIME_BITS=64"
  ])]
)
AX_COMPILE_CHECK_SIZEOF(time_t)
AS_IF([test $ac_size -lt 8], [AC_MSG_ERROR([size of time_t is $ac_size, which is not large enough to fix the y2k38 bug])])
AX_CHECK_SIGN([time_t], [:], [AC_MSG_ERROR([time_t is unsigned, PowerDNS code relies on it being signed])], [
  #include <sys/types.h>
])
])
