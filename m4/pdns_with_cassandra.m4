AC_DEFUN([PDNS_WITH_CASSANDRA],[
  AC_ARG_WITH([cassandra],
    [AS_HELP_STRING([--with-cassandra=<path>], [root directory path of Cassandra installation])],
    [
      CASSANDRA_LIBS_check="$withval/lib $with_cassandra/lib"
      CASSANDRA_CFLAGS_check="$withval/include"
    ],
    [
      CASSANDRA_LIBS_check="/usr/lib /usr/lib64 /usr/local/lib64 /usr/local/lib $full_libdir"
      CASSANDRA_CFLAGS_check="/usr/local/include /usr/include"
    ]
  )

  AC_ARG_WITH([cassandra-lib],
    [AS_HELP_STRING([--with-cassandra-lib=<path>], [directory path of Cassandra library installation])],
    [
      CASSANDRA_LIBS_check="$withval/lib/cassandra $withval/cassandra $withval"
    ]
  )

  AC_ARG_WITH([cassandra-includes],
    [AS_HELP_STRING([--with-cassandra-includes=<path>], [directory path of Cassandra header installation])],
    [
      CASSANDRA_CFLAGS_check="$withval/include/cassandra $withval/cassandra $withval"
    ]
  )
  
  AC_MSG_CHECKING([for Cassandra library directory])
    CASSANDRA_libdir=
    for m in $CASSANDRA_LIBS_check; do
      if test -d "$m" && \
        (test -f "$m/libcassandra.so" || test -f "$m/libcassandra_static.a")
      then
        CASSANDRA_libdir=$m
        break
      fi
    done

    if test -z "$CASSANDRA_libdir"; then
      AC_MSG_ERROR([Did not find the cassandra library dir in '$CASSANDRA_LIBS_check'])
    fi
    case "$CASSANDRA_libdir" in
      /*) CASSANDRA_LIBS="-L$CASSANDRA_libdir -lcassandra"
          ;;
      *)  AC_MSG_ERROR([The Cassandra library directory ($CASSANDRA_libdir) must be an absolute path.])
          ;;
    esac
    AC_MSG_RESULT([$CASSANDRA_libdir])
    AC_SUBST(CASSANDRA_LIBS)
    AC_MSG_CHECKING([for Cassandra include directory])
    CASSANDRA_CFLAGS=
    for m in $CASSANDRA_CFLAGS_check; do
      if test -d "$m" && test -f "$m/cassandra.h"
      then
        CASSANDRA_CFLAGS="$m"
        break
      fi
    done
    if test -z "$CASSANDRA_CFLAGS"; then
      AC_MSG_ERROR([Did not find the cassandra include dir in '$CASSANDRA_CFLAGS_check'])
    fi

    case "$CASSANDRA_CFLAGS" in
      /*) AC_MSG_RESULT($CASSANDRA_CFLAGS)
          ;;
      *)  AC_MSG_ERROR([The Cassandra include directory ($CASSANDRA_CFLAGS) must be an absolute path.])
          ;;
    esac
    CASSANDRA_CFLAGS="-I$CASSANDRA_CFLAGS"
    
  AC_SUBST(CASSANDRA_LIBS)
  AC_SUBST(CASSANDRA_CFLAGS)
])


