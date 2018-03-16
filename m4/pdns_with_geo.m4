AC_DEFUN([PDNS_CHECK_GEOIP], [
  PKG_CHECK_MODULES([GEOIP], [geoip], AC_DEFINE([HAVE_GEOIP], [1], [Define this if you have GeoIP]), [have_geoip=0])
  AC_ARG_WITH([maxminddb_incdir],
    AS_HELP_STRING([--with-maxminddb-includedir],[path to maxminddb include directory @<:@default=auto@:>@]),
    [with_maxminddb_incdir=$withval],
    [with_maxminddb_incdir=auto]
  )
  AC_ARG_WITH([maxminddb_libdir],
    AS_HELP_STRING([--with-maxminddb-libdir],[path to maxminddb library directory @<:@default=auto@:>@]),
    [with_maxminddb_libdir=$withval],
    [with_maxminddb_libdir=auto],
  )

  PKG_CHECK_MODULES([MMDB], [libmaxminddb], [
    AC_DEFINE([HAVE_MMDB], [1], [Define this if you have Maxmind DB])
  ], [
    AS_IF([test "x$with_maxminddb_incdir" = "xauto"], [
      AC_CHECK_HEADER([maxminddb.h], [have_mmdb=1], [have_mmdb=0])
    ], [
      OLD_CFLAGS="$CFLAGS"
      CFLAGS="$CFLAGS -I$with_maxminddb_incdir"
      AC_CHECK_HEADER([maxminddb.h], [have_mmdb=1], [have_mmdb=0])
      CFLAGS="$OLD_CFLAGS"
    ])

    AS_IF([test "$have_mmdb" = "1"], [
      AS_IF([test "x$with_maxminddb_libdir" = "xauto"], [
        AC_CHECK_LIB([maxminddb], [MMDB_open], [
          AC_DEFINE([HAVE_MMDB], [1], [Define this if you have Maxmind DB])
          MMDB_LIBS="-lmaxminddb"
        ])
      ], [
        OLD_LDFLAGS="$LDFLAGS"
        LDFLAGS="$LDFLAGS -L$with_maxminddb_libdir"
        AC_CHECK_LIB([maxminddb], [MMDB_open], [
          AC_DEFINE([HAVE_MMDB], [1], [Define this if you have Maxmind DB])
          MMDB_CFLAGS="-I$with_maxminddb_incdir"
          MMDB_LIBS="-L$with_maxminddb_libdir -lmaxminddb"
        ])
      ])
    ])
  ])

  PKG_CHECK_MODULES([YAML], [yaml-cpp >= 0.5],[],
    AC_MSG_ERROR([Could not find yaml-cpp])
  )
])
