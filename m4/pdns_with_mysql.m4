AC_DEFUN([PDNS_WITH_MYSQL],[
  AC_ARG_WITH([mysql],
    [AS_HELP_STRING([--with-mysql=<path>], [root directory path of MySQL installation])],
    [
      MYSQL_lib_check="$withval/lib/mysql $with_mysql/lib"
      MYSQL_inc_check="$withval/include/mysql"
      MYSQL_config_check="$withval/bin/mysql_config"
    ],
    [
      MYSQL_lib_check="/usr/local/mysql/lib/mysql /usr/local/lib/mysql /opt/mysql/lib/mysql \
        /usr/lib/mysql /usr/lib64/mysql /usr/local/mysql/lib /usr/local/lib /opt/mysql/lib /usr/lib \
        /usr/sfw/lib/ $full_libdir"
      MYSQL_inc_check="/usr/local/mysql/include/mysql /usr/local/include/mysql \
        /opt/mysql/include/mysql /opt/mysql/include /usr/include/mysql /usr/sfw/include/mysql"
    ]
  )

  AC_ARG_WITH([mysql-config],
    [AS_HELP_STRING([--with-mysql-config=<path>], [file path to mysql_config])],
    [MYSQL_config_check=$withval]
  )

  AC_ARG_WITH([mysql-lib],
    [AS_HELP_STRING([--with-mysql-lib=<path>], [directory path of MySQL library installation])],
    [
      MYSQL_lib_check="$withval/lib/mysql $withval/mysql $withval"
      MYSQL_config_check="skip"
    ]
  )

  AC_ARG_WITH([mysql-includes],
    [AS_HELP_STRING([--with-mysql-includes=<path>], [directory path of MySQL header installation])],
    [
      MYSQL_inc_check="$withval/include/mysql $withval/mysql $withval"
      MYSQL_config_check="skip"
    ]
  )

  MYSQL_config=""
  if test "x$MYSQL_config_check" != "xskip"; then
    AC_MSG_CHECKING([for mysql_config])
    if test "x$MYSQL_config_check" = "x"; then
      # check if it's in path
      for m in /bin /usr/bin /usr/local/bin /opt/csw/bin; do
        if test -x $m/mysql_config; then
          MYSQL_config=$m/mysql_config
          break
        fi
      done

      if test "x$MYSQL_config" = "x"; then
        AC_MSG_RESULT([not found])
      else
        AC_MSG_RESULT([$MYSQL_config])
      fi
    else
      if test -x $MYSQL_config_check; then
        MYSQL_config="$MYSQL_config_check"
        AC_MSG_RESULT([$MYSQL_config])
      else
        MYSQL_config=""
        AC_MSG_ERROR([not found])
      fi
    fi
  fi

  if test "x$MYSQL_config" != "x"; then
    # use this to configure everything
    MYSQL_lib=`$MYSQL_config --libs`
    MYSQL_inc=`$MYSQL_config --include`
  else
    AC_MSG_CHECKING([for MySQL library directory])
    MYSQL_libdir=
    for m in $MYSQL_lib_check; do
      if test -d "$m" && \
        (test -f "$m/libmysqlclient.so" || test -f "$m/libmysqlclient.a")
      then
        MYSQL_libdir=$m
        break
      fi
    done
    if test -z "$MYSQL_libdir"; then
      AC_MSG_ERROR([Did not find the mysql library dir in '$MYSQL_lib_check'])
    fi
    case "$MYSQL_libdir" in
      /*) MYSQL_lib="-L$MYSQL_libdir -lmysqlclient"
          ;;
      *)  AC_MSG_ERROR([The MySQL library directory ($MYSQL_libdir) must be an absolute path.])
          ;;
    esac
    AC_MSG_RESULT([$MYSQL_libdir])
    AC_SUBST(MYSQL_lib)
    AC_MSG_CHECKING([for MySQL include directory])
    MYSQL_inc=
    for m in $MYSQL_inc_check; do
      if test -d "$m" && test -f "$m/mysql.h"
      then
        MYSQL_inc="$m"
        break
      fi
    done
    if test -z "$MYSQL_inc"; then
      AC_MSG_ERROR([Did not find the mysql include dir in '$MYSQL_inc_check'])
    fi

    case "$MYSQL_inc" in
      /*) AC_MSG_RESULT($MYSQL_inc)
          ;;
      *)  AC_MSG_ERROR([The MySQL include directory ($MYSQL_inc) must be an absolute path.])
          ;;
    esac
    MYSQL_inc="-I$MYSQL_inc"
  fi
  AC_SUBST(MYSQL_lib)
  AC_SUBST(MYSQL_inc)
])

