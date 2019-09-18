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

AC_DEFUN([AX_CHECK_SYSTEMD_FEATURES], [
        AS_IF([test x"$systemd" = "xy"], [
          AC_PATH_PROG([SYSTEMCTL], [systemctl], [no])
          AS_IF([test "$SYSTEMCTL" = "no"],
            [AC_MSG_ERROR([systemctl not found])], [
              _systemd_version=`${SYSTEMCTL} --version|head -1 |cut -d" " -f 2`
              if test $_systemd_version -ge 183; then
                 systemd_private_tmp=y
              fi
              if test $_systemd_version -ge 209; then
                 systemd_system_call_architectures=y
                 systemd_private_devices=y
              fi
              if test $_systemd_version -ge 211; then
                 systemd_restrict_address_families=y
              fi
              if test $_systemd_version -ge 214; then
                 systemd_protect_system=y
                 systemd_protect_home=y
              fi
              if test $_systemd_version -ge 231; then
                 systemd_restrict_realtime=y
                 systemd_memory_deny_write_execute=y
              fi
              if test $_systemd_version -ge 232; then
                 systemd_protect_control_groups=y
                 systemd_protect_kernel_modules=y
                 systemd_protect_kernel_tunables=y
                 systemd_remove_ipc=y
                 systemd_dynamic_user=y
                 systemd_private_users=y
                 systemd_protect_system_strict=y
              fi
              if test $_systemd_version -ge 233; then
                 systemd_restrict_namespaces=y
              fi
              if test $_systemd_version -ge 235; then
                 systemd_lock_personality=y
                 # while SystemCallFilter is technically available starting with 187,
                 # we use the pre-defined call filter sets that have been introduced later.
                 # Initial support for these landed in 231
                 # @filesystem @reboot @swap in 233
                 # @aio, @sync, @chown, @setuid, @memlock, @signal and @timer in 235
                 systemd_system_call_filter=y
              fi
          ])
        ])
        AM_CONDITIONAL([HAVE_SYSTEMD_DYNAMIC_USER], [ test x"$systemd_dynamic_user" = "xy" ])
        AM_CONDITIONAL([HAVE_SYSTEMD_LOCK_PERSONALITY], [ test x"$systemd_lock_personality" = "xy" ])
        AM_CONDITIONAL([HAVE_SYSTEMD_MEMORY_DENY_WRITE_EXECUTE], [ test x"$systemd_memory_deny_write_execute" = "xy" ])
        AM_CONDITIONAL([HAVE_SYSTEMD_PRIVATE_DEVICES], [ test x"$systemd_private_devices" = "xy" ])
        AM_CONDITIONAL([HAVE_SYSTEMD_PRIVATE_TMP], [ test x"$systemd_private_tmp" = "xy" ])
        AM_CONDITIONAL([HAVE_SYSTEMD_PRIVATE_USERS], [ test x"$systemd_private_users" = "xy" ])
        AM_CONDITIONAL([HAVE_SYSTEMD_PROTECT_CONTROL_GROUPS], [ test x"$systemd_protect_control_groups" = "xy" ])
        AM_CONDITIONAL([HAVE_SYSTEMD_PROTECT_HOME], [ test x"$systemd_protect_home" = "xy" ])
        AM_CONDITIONAL([HAVE_SYSTEMD_PROTECT_KERNEL_MODULES], [ test x"$systemd_protect_kernel_modules" = "xy" ])
        AM_CONDITIONAL([HAVE_SYSTEMD_PROTECT_KERNEL_TUNABLES], [ test x"$systemd_protect_kernel_tunables" = "xy" ])
        AM_CONDITIONAL([HAVE_SYSTEMD_PROTECT_SYSTEM], [ test x"$systemd_protect_system" = "xy" ])
        AM_CONDITIONAL([HAVE_SYSTEMD_PROTECT_SYSTEM_STRICT], [ test x"$systemd_protect_system_strict" = "xy" ])
        AM_CONDITIONAL([HAVE_SYSTEMD_REMOVE_IPC], [ test x"$systemd_remove_ipc" = "xy" ])
        AM_CONDITIONAL([HAVE_SYSTEMD_RESTRICT_ADDRESS_FAMILIES], [ test x"$systemd_restrict_address_families" = "xy" ])
        AM_CONDITIONAL([HAVE_SYSTEMD_RESTRICT_NAMESPACES], [ test x"$systemd_restrict_namespaces" = "xy" ])
        AM_CONDITIONAL([HAVE_SYSTEMD_RESTRICT_REALTIME], [ test x"$systemd_restrict_realtime" = "xy" ])
        AM_CONDITIONAL([HAVE_SYSTEMD_RESTRICT_SUIDSGID], [ test x"$systemd_restrict_suidsgid" = "xy" ])
        AM_CONDITIONAL([HAVE_SYSTEMD_SYSTEM_CALL_ARCHITECTURES], [ test x"$systemd_system_call_architectures" = "xy" ])
        AM_CONDITIONAL([HAVE_SYSTEMD_SYSTEM_CALL_FILTER], [ test x"$systemd_system_call_filter" = "xy" ])
])
