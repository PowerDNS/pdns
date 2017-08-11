# systemd.m4 - Macros to check for and enable systemd          -*- Autoconf -*-
#
# Copyright (C) 2014 Luis R. Rodriguez <mcgrof@suse.com>
# Copyright (C) 2016 Pieter Lexis <pieter.lexis@powerdns.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

#serial 2

dnl Some optional path options
AC_DEFUN([AX_SYSTEMD_OPTIONS], [
	AC_ARG_WITH(systemd, [  --with-systemd          set directory for systemd service files],
		SYSTEMD_DIR="$withval", SYSTEMD_DIR="")
	AC_SUBST(SYSTEMD_DIR)

	AC_ARG_WITH(systemd, [  --with-systemd-modules-load          set directory for systemd modules load files],
		SYSTEMD_MODULES_LOAD="$withval", SYSTEMD_MODULES_LOAD="")
	AC_SUBST(SYSTEMD_MODULES_LOAD)
])

AC_DEFUN([AX_ENABLE_SYSTEMD_OPTS], [
	AX_ARG_DEFAULT_ENABLE([systemd], [Disable systemd support])
	AX_SYSTEMD_OPTIONS()
])

AC_DEFUN([AX_ALLOW_SYSTEMD_OPTS], [
	AX_ARG_DEFAULT_DISABLE([systemd], [Enable systemd support], [$1])
	AX_SYSTEMD_OPTIONS()
])

AC_DEFUN([AX_CHECK_SYSTEMD_LIBS], [
	AC_REQUIRE([AX_CHECK_SYSTEMD_DETECT_AND_ENABLE])
	AS_IF([test "x$libsystemd" = x], [
	    AC_MSG_ERROR([Unable to find a suitable libsystemd library])
	])

	PKG_CHECK_MODULES([SYSTEMD], [$libsystemd_daemon])
	dnl pkg-config older than 0.24 does not set these for
	dnl PKG_CHECK_MODULES() worth also noting is that as of version 208
	dnl of systemd pkg-config --cflags currently yields no extra flags yet.
	AC_SUBST([SYSTEMD_CFLAGS])
	AC_SUBST([SYSTEMD_LIBS])

	AS_IF([test "x$SYSTEMD_DIR" = x], [
	    dnl In order to use the line below we need to fix upstream systemd
	    dnl to properly ${prefix} for child variables in
	    dnl src/core/systemd.pc.in but this is a bit complex at the
	    dnl moment as they depend on another rootprefix, which can vary
	    dnl from prefix in practice. We provide our own definition as we
	    dnl *know* where systemd will dump this to, but this does limit
	    dnl us to stick to a non custom systemdsystemunitdir, dnl to work
	    dnl around this we provide the additional configure option
	    dnl --with-systemd where you can specify the directory for the unit
	    dnl files. It would also be best to just extend the upstream
	    dnl pkg-config  pkg.m4 with an AC_DEFUN() to do this neatly.
	    dnl SYSTEMD_DIR="`$PKG_CONFIG --define-variable=prefix=$PREFIX --variable=systemdsystemunitdir systemd`"
	    SYSTEMD_DIR="\$(prefix)/lib/systemd/system/"
	], [])

	AS_IF([test "x$SYSTEMD_DIR" = x], [
	    AC_MSG_ERROR([SYSTEMD_DIR is unset])
	], [])

	dnl There is no variable for this yet for some reason
	AS_IF([test "x$SYSTEMD_MODULES_LOAD" = x], [
	    SYSTEMD_MODULES_LOAD="\$(prefix)/lib/modules-load.d/"
	], [])

	AS_IF([test "x$SYSTEMD_MODULES_LOAD" = x], [
	    AC_MSG_ERROR([SYSTEMD_MODULES_LOAD is unset])
	], [])
])

AC_DEFUN([AX_CHECK_SYSTEMD], [
	dnl Respect user override to disable
	AS_IF([test "x$enable_systemd" != "xno"], [
	     AS_IF([test "x$systemd" = "xy" ], [
		AC_DEFINE([HAVE_SYSTEMD], [1], [Systemd available and enabled])
			systemd=y
			AX_CHECK_SYSTEMD_LIBS()
	    ],[systemd=n])
	],[systemd=n])
])

AC_DEFUN([AX_CHECK_SYSTEMD_DETECT_AND_ENABLE], [
	AC_CHECK_HEADER([systemd/sd-daemon.h], [
		for libname in systemd-daemon systemd; do
			AC_CHECK_LIB([$libname], [sd_listen_fds], [
				libsystemd_daemon="lib$libname"
				systemd=y
				libsystemd=y
			])
		done
	])
])

dnl Enables systemd by default and requires a --disable-systemd option flag
dnl to configure if you want to disable.
AC_DEFUN([AX_ENABLE_SYSTEMD], [
	AX_ENABLE_SYSTEMD_OPTS()
	AX_CHECK_SYSTEMD()
])

dnl Systemd will be disabled by default and requires you to run configure with
dnl --enable-systemd to look for and enable systemd.
AC_DEFUN([AX_ALLOW_SYSTEMD], [
	AX_ALLOW_SYSTEMD_OPTS()
	AX_CHECK_SYSTEMD()
])

dnl Systemd will be disabled by default but if your build system is detected
dnl to have systemd build libraries it will be enabled. You can always force
dnl disable with --disable-systemd
AC_DEFUN([AX_AVAILABLE_SYSTEMD], [
	AX_ALLOW_SYSTEMD_OPTS([, but will be enabled when libraries are found])
	AX_CHECK_SYSTEMD_DETECT_AND_ENABLE()
	AX_CHECK_SYSTEMD()
])
