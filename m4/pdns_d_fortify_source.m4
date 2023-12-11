dnl
dnl Check for support D_FORTIFY_SOURCE
dnl
dnl Copyright (C) 2013 Red Hat, Inc.
dnl
dnl This library is free software; you can redistribute it and/or
dnl modify it under the terms of the GNU Lesser General Public
dnl License as published by the Free Software Foundation; either
dnl version 2.1 of the License, or (at your option) any later version.
dnl
dnl This library is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl Lesser General Public License for more details.
dnl
dnl You should have received a copy of the GNU Lesser General Public
dnl License along with this library.  If not, see
dnl <http://www.gnu.org/licenses/>.
dnl

AC_DEFUN([AC_CC_D_FORTIFY_SOURCE],[
  AC_ARG_ENABLE([fortify-source],
    AS_HELP_STRING([--enable-fortify-source], [enable FORTIFY_SOURCE support @<:@default=2@:>@]),
    [enable_fortify_source=$enableval],
    [enable_fortify_source=2]
  )

  AS_IF([test "x$enable_fortify_source" != "xno"], [

    dnl Auto means the highest version we support, which is currently 3
    AS_IF([test "$enable_fortify_source" = "auto"],
      [enable_fortify_source=3],
      []
    )

    dnl If 3 is not supported, we try to fallback to 2
    AS_IF([test "$enable_fortify_source" = "3"], [
      gl_COMPILER_OPTION_IF([-D_FORTIFY_SOURCE=3], [
        CFLAGS="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 $CFLAGS"
        CXXFLAGS="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 $CXXFLAGS"
      ], [enable_fortify_source=2])
    ])

    dnl If 2 is not supported, we try to fallback to 1
    AS_IF([test "$enable_fortify_source" = "2"], [
      gl_COMPILER_OPTION_IF([-D_FORTIFY_SOURCE=2], [
        CFLAGS="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 $CFLAGS"
        CXXFLAGS="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 $CXXFLAGS"
      ], [enable_fortify_source=1])
    ])

    AS_IF([test "$enable_fortify_source" = "1"], [
      gl_COMPILER_OPTION_IF([-D_FORTIFY_SOURCE=1], [
        CFLAGS="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=1 $CFLAGS"
        CXXFLAGS="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=1 $CXXFLAGS"
      ], [enable_fortify_source=no])
    ])

  ])

  AC_MSG_CHECKING([whether FORTIFY_SOURCE is supported])
  AC_MSG_RESULT([$enable_fortify_source])
])
