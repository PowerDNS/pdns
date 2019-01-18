AC_DEFUN([PDNS_WITH_MYSQL],[
  AC_ARG_WITH([mysql],
    [AS_HELP_STRING([--with-mysql=<path>], [root directory path of MySQL installation])],
    [
      if test "$withval" = "no"; then
        modules_without_gmysql=$(echo $modules|sed -e 's/gmysql//;s/  */ /g;')
        dynmodules_without_gmysql=$(echo $dynmodules|sed -e 's/gmysql//;s/  */ /g;')
        AC_MSG_ERROR([instead of --without-mysql try --with-modules="$modules_without_gmysql" --with-dyn-modules="$dynmodules_without_gmysql"])
      fi

      MYSQL_LIBS_check="$withval/lib/mysql $with_mysql/lib"
      MYSQL_CFLAGS_check="$withval/include/mysql"
      MYSQL_config_check="$withval/bin/mysql_config"
    ],
    [
      MYSQL_LIBS_check="/usr/local/mysql/lib/mysql /usr/local/lib/mysql /opt/mysql/lib/mysql \
        /usr/lib/mysql /usr/lib64/mysql /usr/local/mysql/lib /usr/local/lib /opt/mysql/lib /usr/lib \
        /usr/sfw/lib/ $full_libdir"
      MYSQL_CFLAGS_check="/usr/local/mysql/include/mysql /usr/local/include/mysql \
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
      MYSQL_LIBS_check="$withval/lib/mysql $withval/mysql $withval"
      MYSQL_config_check="skip"
    ]
  )

  AC_ARG_WITH([mysql-includes],
    [AS_HELP_STRING([--with-mysql-includes=<path>], [directory path of MySQL header installation])],
    [
      MYSQL_CFLAGS_check="$withval/include/mysql $withval/mysql $withval"
      MYSQL_config_check="skip"
    ]
  )

  MYSQL_config=""
  if test "x$MYSQL_config_check" != "xskip"; then
    if test "x$MYSQL_config_check" = "x"; then
      AC_PATH_PROG([MYSQL_config], [mysql_config])
    else
      AC_MSG_CHECKING([for $MYSQL_config_check])
      if test -x $MYSQL_config_check; then
        MYSQL_config="$MYSQL_config_check"
        AC_MSG_RESULT([yes])
      else
        MYSQL_config=""
        AC_MSG_ERROR([not found])
      fi
    fi
  fi

  if test "x$MYSQL_config" != "x"; then
    # use this to configure everything
    MYSQL_LIBS=`$MYSQL_config --libs`
    MYSQL_CFLAGS=`$MYSQL_config --include`
  else
    AC_MSG_CHECKING([for MySQL library directory])
    MYSQL_libdir=
    for m in $MYSQL_LIBS_check; do
      if test -d "$m" && \
        (test -f "$m/libmysqlclient.so" || test -f "$m/libmysqlclient.a")
      then
        MYSQL_libdir=$m
        break
      fi
    done
    if test -z "$MYSQL_libdir"; then
      AC_MSG_ERROR([Did not find the mysql library dir in '$MYSQL_LIBS_check'])
    fi
    case "$MYSQL_libdir" in
      /*) MYSQL_LIBS="-L$MYSQL_libdir -lmysqlclient"
          ;;
      *)  AC_MSG_ERROR([The MySQL library directory ($MYSQL_libdir) must be an absolute path.])
          ;;
    esac
    AC_MSG_RESULT([$MYSQL_libdir])
    AC_SUBST(MYSQL_LIBS)
    AC_MSG_CHECKING([for MySQL include directory])
    MYSQL_CFLAGS=
    for m in $MYSQL_CFLAGS_check; do
      if test -d "$m" && test -f "$m/mysql.h"
      then
        MYSQL_CFLAGS="$m"
        break
      fi
    done
    if test -z "$MYSQL_CFLAGS"; then
      AC_MSG_ERROR([Did not find the mysql include dir in '$MYSQL_CFLAGS_check'])
    fi

    case "$MYSQL_CFLAGS" in
      /*) AC_MSG_RESULT($MYSQL_CFLAGS)
          ;;
      *)  AC_MSG_ERROR([The MySQL include directory ($MYSQL_CFLAGS) must be an absolute path.])
          ;;
    esac
    MYSQL_CFLAGS="-I$MYSQL_CFLAGS"
  fi
  AC_SUBST(MYSQL_LIBS)
  AC_SUBST(MYSQL_CFLAGS)
])

