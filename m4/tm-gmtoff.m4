dnl Check for the tm_gmtoff field in struct tm
dnl (Borrowed from the Gaim project)
dnl The Gaim Project (now know as Pidgin) is licensed under the GPLv2

AC_DEFUN([MC_TM_GMTOFF],
  [AC_REQUIRE([AC_STRUCT_TM])dnl
  AC_CACHE_CHECK([for tm_gmtoff in struct tm],
    ac_cv_struct_tm_gmtoff,
    [
      AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
#include <sys/types.h>
#include <$ac_cv_struct_tm>
struct tm tm; tm.tm_gmtoff;
      ]]),
      ac_cv_struct_tm_gmtoff=yes,
      ac_cv_struct_tm_gmtoff=no])
    ]
  )
  if test "$ac_cv_struct_tm_gmtoff" = yes; then
    AC_DEFINE(HAVE_TM_GMTOFF, 1, [tm_gmtoff is available.])
  fi
])
