AC_DEFUN([PDNS_WITH_ORACLE],[
  AC_ARG_WITH(oracle_includes, AS_HELP_STRING([--with-oracle-includes=<path>],[instantclient sdk include dir]))
  AC_ARG_WITH(oracle_libs, AS_HELP_STRING([--with-oracle-libs=<path>],[instantclient oracle library dir]))

  if test x"$with_oracle_includes" = "x"; then
    # check possible locations
    for p1 in /usr/include/oracle /usr/local/include/oracle; do
      for p2 in $p1/*/client*; do
        if test -d "$p2"; then
          with_oracle_includes=$p2
        fi
      done
    done
  fi

  if test x"$with_oracle_includes" = x && test "$ORACLE_HOME/rdbms/public" != "/rdbms/public"; then
    if test -d $ORACLE_HOME/rdbms/public; then
      with_oracle_includes=$ORACLE_HOME/rdbms/public
    fi
  fi

  # test header
  old_CXXFLAGS="$CXXFLAGS"
  old_CFLAGS="$CFLAGS"
  CXXFLAGS="$CXXFLAGS -I$with_oracle_includes"
  CPPFLAGS="$CPPFLAGS -I$with_oracle_includes"
  AC_CHECK_HEADER([oci.h], ORACLE_CFLAGS="-I$with_oracle_includes", AC_MSG_ERROR([Could not find oci.h]))
  CXXFLAGS="$old_CXXFLAGS"
  CPPFLAGS="$old_CPPFLAGS"
  AC_SUBST([ORACLE_CFLAGS])
  AC_SUBST([ORACLE_LIBS])

  if test x"$with_oracle_libs" = "x"; then
     # check possible locations
     for p1 in /usr/lib/oracle /usr/local/lib/oracle; do
       for p2 in $p1/*/client*/lib; do
         if test -d "$p2"; then
           with_oracle_libs=$p2
         fi
       done
     done
  fi

  if test x"$with_oracle_libs" = x && test "$ORACLE_HOME/lib" != "/lib"; then
    if test -d $ORACLE_HOME/lib; then
      with_oracle_libs=$ORACLE_HOME/lib
    fi
  fi

  # we have to check for client9 as well...
  # test -lclntsh
  old_LDFLAGS="$LDFLAGS"
  LDFLAGS="-L$with_oracle_libs -locci"
  AC_CHECK_LIB([clntsh],[OCIEnvInit],
    [ORACLE_LIBS="-L$with_oracle_libs -lclntsh -locci"],
    AC_CHECK_LIB([client9], [OCIEnvInit],
      [ORACLE_LIBS="-L$with_oracle_libs -lclient9 -lclntsh9"],
      [AC_MSG_ERROR([Could not find client libraries])]
    )
  )
  LDFLAGS="$old_LDFLAGS"
])
