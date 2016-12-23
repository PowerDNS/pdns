AC_DEFUN([PDNS_WITH_UNIXODBC],[
  AC_ARG_WITH([unixodbc],
    [AS_HELP_STRING([--with-unixodbc=<path>], [root directory path of unixODBC installation])],
    [
      UNIXODBC_LIBS_check="$withval/lib/unixodbc $with_unixodbc/lib"
      UNIXODBC_CFLAGS_check="$withval/include/unixodbc"
      UNIXODBC_config_check="$withval/bin/odbc_config"
    ],
    [
      UNIXODBC_LIBS_check="/usr/local/unixodbc/lib/unixodbc /usr/local/lib/unixodbc /opt/unixodbc/lib/unixodbc \
        /usr/lib/unixodbc /usr/lib64/unixodbc /usr/local/unixodbc/lib /usr/local/lib /opt/unixodbc/lib /usr/lib \
        /usr/sfw/lib/ /usr/lib/odbc /usr/lib/x86_64-linux-gnu $full_libdir"
      UNIXODBC_CFLAGS_check="/usr/local/unixodbc/include/unixodbc /usr/local/include/unixodbc \
        /opt/unixodbc/include/unixodbc /opt/unixodbc/include /usr/include/unixodbc /usr/sfw/include/unixodbc \
        /usr/include /usr/local/include"
    ]
  )

  AC_ARG_WITH([odbc-config],
    [AS_HELP_STRING([--with-odbc-config=<path>], [file path to odbc_config])],
    [UNIXODBC_config_check=$withval]
  )

  AC_ARG_WITH([unixodbc-lib],
    [AS_HELP_STRING([--with-unixodbc-lib=<path>], [directory path of unixODBC library installation])],
    [
      UNIXODBC_LIBS_check="$withval/lib/unixodbc $withval/unixodbc $withval"
      UNIXODBC_config_check="skip"
    ]
  )

  AC_ARG_WITH([unixodbc-includes],
    [AS_HELP_STRING([--with-unixodbc-includes=<path>], [directory path of unixODBC header installation])],
    [
      UNIXODBC_CFLAGS_check="$withval/include/unixodbc $withval/unixodbc $withval"
      UNIXODBC_config_check="skip"
    ]
  )

  UNIXODBC_config=""
  if test "x$UNIXODBC_config_check" != "xskip"; then
    if test "x$UNIXODBC_config_check" = "x"; then
      AC_PATH_PROG([UNIXODBC_config], [odbc_config])
    else
      AC_MSG_CHECKING([for $UNIXODBC_config_check])
      if test -x $UNIXODBC_config_check; then
        UNIXODBC_config="$UNIXODBC_config_check"
        AC_MSG_RESULT([yes])
      else
        UNIXODBC_config=""
        AC_MSG_ERROR([not found])
      fi
    fi
  fi

  if test "x$UNIXODBC_config" != "x"; then
    # use this to configure everything
    UNIXODBC_LIBS=`$UNIXODBC_config --libs`
    UNIXODBC_CFLAGS=-I`$UNIXODBC_config --include-prefix`
  else
    AC_MSG_CHECKING([for unixODBC library directory])
    UNIXODBC_libdir=
    for m in $UNIXODBC_LIBS_check; do
      if test -d "$m" && \
        (test -f "$m/libodbc.so" || test -f "$m/libodbc.a")
      then
        UNIXODBC_libdir=$m
        break
      fi
    done
    if test -z "$UNIXODBC_libdir"; then
      AC_MSG_ERROR([Did not find the unixodbc library dir in '$UNIXODBC_LIBS_check'])
    fi
    case "$UNIXODBC_libdir" in
      /*) UNIXODBC_LIBS="-L$UNIXODBC_libdir -lodbc"
          ;;
      *)  AC_MSG_ERROR([The unixODBC library directory ($UNIXODBC_libdir) must be an absolute path.])
          ;;
    esac
    AC_MSG_RESULT([$UNIXODBC_libdir])

    AC_MSG_CHECKING([for unixODBC include directory])
    UNIXODBC_CFLAGS=
    for m in $UNIXODBC_CFLAGS_check; do
      if test -d "$m" && test -f "$m/sql.h"
      then
        UNIXODBC_CFLAGS="$m"
        break
      fi
    done
    if test -z "$UNIXODBC_CFLAGS"; then
      AC_MSG_ERROR([Did not find the unixodbc include dir in '$UNIXODBC_CFLAGS_check'])
    fi

    case "$UNIXODBC_CFLAGS" in
      /*) AC_MSG_RESULT($UNIXODBC_CFLAGS)
          ;;
      *)  AC_MSG_ERROR([The unixODBC include directory ($UNIXODBC_CFLAGS) must be an absolute path.])
          ;;
    esac
    UNIXODBC_CFLAGS="-I$UNIXODBC_CFLAGS"
  fi

  AC_SUBST(UNIXODBC_CFLAGS)
  AC_SUBST(UNIXODBC_LIBS)
])
