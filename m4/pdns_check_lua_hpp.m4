AC_DEFUN([PDNS_CHECK_LUA_HPP],[
  AC_REQUIRE([PDNS_WITH_LUA])
  AC_REQUIRE([PDNS_WITH_LUAJIT])
  AS_IF([test "x$LUAPC" != "x" -o "x$LUAJITPC" != "x" ], [
    AC_CHECK_HEADER([lua.hpp], [ have_lua_hpp=y ])
  ])
  AM_CONDITIONAL([HAVE_LUA_HPP], [ test x"$have_lua_hpp" = "xy" ])
])
