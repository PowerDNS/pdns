AC_DEFUN([PDNS_WITH_LUA],[
  AC_PROG_GREP()dnl Ensure we have grep
  AC_MSG_CHECKING([which Lua implementation to use])
  AC_ARG_WITH([lua],
    [AS_HELP_STRING([--with-lua], [select Lua implementation @<:@default=auto@:>@])
  ], [
    with_lua=$withval
  ], [
    with_lua=auto
  ])

  AS_IF([test "x$with_lua" = "xyes"], [
    dnl --with-lua was passed, make it auto
    with_lua=auto
  ])

  AC_MSG_RESULT([$with_lua])

  AS_IF([test "x$with_lua" = "xno" -a "$1" = "mandatory"], [
    AC_MSG_ERROR([--without-lua specified, but Lua is not optional])
  ])

  LUAPC=""
  luajit_min_version='2.0.2'
  lua_min_version='5.1'

  AS_IF([test "x$with_lua" != "xno"], [
    AS_IF([test "x$with_lua" != "xauto"], [
      with_lua_version=${lua_min_version}
      AS_IF([echo "x$with_lua" | ${GREP} 'jit' >/dev/null 2>&1], [with_lua_version=${luajit_min_version}])
      PKG_CHECK_MODULES([LUA], $with_lua >= $with_lua_version, [
        AC_DEFINE([HAVE_LUA], [1], [Define to 1 if you have Lua])
        LUAPC=$with_lua
      ], [
        AC_MSG_ERROR([Selected Lua ($with_lua) not found])
      ])
    ], [
      PKG_CHECK_MODULES([LUA], [luajit >= ${luajit_min_version}], [
        LUAPC=luajit
        AC_DEFINE([HAVE_LUA], [1], [Define to 1 if you have Lua])
      ], [ : ])
      AS_IF([test -z "$LUAPC"], [
        found_lua=n
        m4_foreach_w([luapc], [lua5.3 lua-5.3 lua53 lua5.2 lua-5.2 lua52 lua5.1 lua-5.1 lua51 lua], [
          AS_IF([test "$found_lua" != "y"], [
            PKG_CHECK_MODULES([LUA], [luapc >= ${lua_min_version}], [
              AC_DEFINE([HAVE_LUA], [1], [Define to 1 if you have lua])
              found_lua=y
              LUAPC=luapc
            ], [ : ])
          ])
        ])
      ])
    ])
  ])

  AS_IF([test -z "$LUAPC" -a "$1" = "mandatory"], [
    AC_MSG_ERROR([No Lua not found, but is mandatory])
  ])

  AM_CONDITIONAL([LUA], [test -n "x$LUAPC"])
])
