dnl
dnl Check for support -fstack-check
dnl
dnl This file is part of PowerDNS or dnsdist.
dnl Copyright -- PowerDNS.COM B.V. and its contributors
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of version 2 of the GNU General Public License as
dnl published by the Free Software Foundation.
dnl
dnl In addition, for the avoidance of any doubt, permission is granted to
dnl link this program with OpenSSL and to (re)distribute the binaries
dnl produced as the result of such linking.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

AC_DEFUN([AC_CC_F_STACK_CHECK],[
      OLD_CXXFLAGS="$CXXFLAGS"
      CXXFLAGS="-Wall -W -Werror $CXXFLAGS"
      gl_COMPILER_OPTION_IF([-fstack-check], [
        CFLAGS="-fstack-check $CFLAGS"
        CXXFLAGS="-fstack-check $OLD_CXXFLAGS"
      ], [CXXFLAGS="$OLD_CXXFLAGS"], [AC_LANG_PROGRAM([[#include <stdio.h>]],[])])
]) 
