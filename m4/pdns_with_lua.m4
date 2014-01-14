AC_DEFUN([PDNS_WITH_LUA],[
  dnl Check for lua
  AC_ARG_WITH([lua],
    [AS_HELP_STRING([--with-lua], [build Lua Bindings @<:@default=yes@:>@])],
    [with_lua=$withval],
    [with_lua=yes])

  AS_IF([test "x$with_lua" != "xno"],[
    AS_IF([test "x$with_lua" = "xyes"],
      [LUAPC=lua],
      [LUAPC=$with_lua])

    PKG_CHECK_MODULES([LUA], $LUAPC >= 5.1, [
      AC_DEFINE([HAVE_LUA], [1], [liblua])
      AC_DEFINE([HAVE_LUA_H], [1], [lua.h])
      with_lua=yes
    ],[
      LUAPC=lua5.1
      PKG_CHECK_MODULES([LUA], $LUAPC >= 5.1, [
        AC_DEFINE([HAVE_LUA], [1], [liblua])
        AC_DEFINE([HAVE_LUA_H], [1], [lua.h])
        with_lua=yes
      ],[
        LUAPC=lua-5.1
        PKG_CHECK_MODULES([LUA], $LUAPC >= 5.1, [
          AC_DEFINE([HAVE_LUA], [1], [liblua])
          AC_DEFINE([HAVE_LUA_H], [1], [lua.h])
          with_lua=yes
        ],[
          with_lua=no
        ])
      ])
    ])
  ])
])
