AC_PREREQ([2.61])

AC_INIT([pdns], m4_esyscmd([build-aux/gen-version]))

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])

AC_SUBST([pdns_configure_args], ["$ac_configure_args"])
AC_DEFINE_UNQUOTED([PDNS_CONFIG_ARGS],
  ["$pdns_configure_args"],
  [pdns configure arguments]
)

AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip tar-ustar -Wno-portability subdir-objects parallel-tests 1.11])
AM_SILENT_RULES([yes])

AC_CANONICAL_HOST
: ${CFLAGS="-Wall -g -O2"}
: ${CXXFLAGS="-Wall -g -O2"}

PDNS_CHECK_DOC_PREQ

AC_CONFIG_FILES([
  Makefile
  docs/Makefile
])
AC_OUTPUT
