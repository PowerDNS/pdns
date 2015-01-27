dnl
dnl Check for support for position independent executables
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

AC_DEFUN([AC_CC_PIE],[
    PIE_CFLAGS=
    PIE_LDFLAGS=
    case "$host" in
      *-*-mingw* | *-*-msvc* | *-*-cygwin* )
         ;; dnl All code is position independent on Win32 target
      *)
      gl_COMPILER_OPTION_IF([-fPIE -DPIE], [
        PIE_CFLAGS="-fPIE -DPIE"
        gl_COMPILER_OPTION_IF([-pie], [
          PIE_LDFLAGS="-pie"
          ], [
            dnl some versions of clang require -Wl,-pie instead of -pie
            gl_COMPILER_OPTION_IF(["-Wl,-pie"], [
              PIE_LDFLAGS="-Wl,-pie"
            ])
          ]
        )]
      )
    esac
    AC_SUBST([PIE_CFLAGS])
    AC_SUBST([PIE_LDFLAGS])
])
