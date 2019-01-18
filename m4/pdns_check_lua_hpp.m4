AC_DEFUN([PDNS_CHECK_LUA_HPP],[
  AC_REQUIRE([PDNS_WITH_LUA])
  AS_IF([test "x$LUAPC" != "x" ], [
    OLD_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS $LUA_CFLAGS"
    AC_CHECK_HEADER([lua.hpp], [ have_lua_hpp=y ])
    CPPFLAGS="$OLD_CPPFLAGS"
  ])
  AM_CONDITIONAL([HAVE_LUA_HPP], [ test x"$have_lua_hpp" = "xy" ])
])
