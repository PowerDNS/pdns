AC_DEFUN([PDNS_WITH_LUA_RECORDS], [
  AC_REQUIRE([PDNS_CHECK_LIBCURL])
  AC_MSG_CHECKING([whether we will enable LUA records])

  AC_ARG_ENABLE([lua-records],
    [AS_HELP_STRING([--disable-lua-records], [disable LUA records support @<:@default=no@:>@])],
    [enable_lua_records=$enableval],
    [enable_lua_records=yes]
  )
  AC_MSG_RESULT([$enable_lua_records])

  AS_IF([test "x$enable_lua_records" != "xno"], [
    AS_IF([test "x$LUAPC" = "x"],
      AC_MSG_ERROR([LUA records need LUA. You can disable this feature with the --disable-lua-records switch or configure a proper LUA installation.])
    )
    AS_IF([test "$HAVE_LIBCURL" != "y"], [
      AC_MSG_ERROR([libcurl minimum version requirement not met. This is required for LUA records. You can disable it with the --disable-lua-records switch or use --with-libcurl to select another curl installation.])
    ])

    AC_DEFINE([HAVE_LUA_RECORDS], [1], [Define if enabling LUA records.])
  ])
  AM_CONDITIONAL([HAVE_LUA_RECORDS], [test "x$enable_lua_records" != "xno"])
])
