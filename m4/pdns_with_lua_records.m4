AC_DEFUN([PDNS_WITH_LUA_RECORDS], [
  AC_MSG_CHECKING([whether we will enable LUA records])

  AC_ARG_ENABLE([lua-records],
    [AS_HELP_STRING([--disable-lua-records], [disable LUA records support @<:@default=no@:>@])],
    [enable_lua_records=$enableval],
    [enable_lua_records=yes]
  )
  AC_MSG_RESULT([$enable_lua_records])

  AS_IF([test "x$enable_lua_records" != "xno"], [
    LIBCURL_CHECK_CONFIG("yes", "7.21.3")
    AC_DEFINE([HAVE_LUA_RECORDS], [1], [Define if enabling LUA records.])
  ])
  AM_CONDITIONAL([HAVE_LUA_RECORDS], [test "x$enable_lua_records" != "xno"])
])
