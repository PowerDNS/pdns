AC_DEFUN([PDNS_WITH_LUA],[
  dnl Check for lua
  AC_ARG_WITH([lua],
    [AS_HELP_STRING([--with-lua], [build Lua Bindings @<:@default=yes@:>@])],
    [with_lua=$withval],
    [with_lua=yes])

  AS_IF([test "x$with_lua" != "xno"],[
    AS_IF([test "x$with_lua" = "xyes"],
      [for LUAPC in lua5.2 lua-5.2 lua5.1 lua-5.1 lua; do
         if test "x$LUA_LIBS" != "x"; then break; fi
         PKG_CHECK_MODULES([LUA], $LUAPC >= 5.1, [
           AC_DEFINE([HAVE_LUA], [1], [liblua])
           AC_DEFINE([HAVE_LUA_H], [1], [lua.h])
         ], [with_lua=yes]) # otherwise pkg_check will fail
       done
      ],       
      [LUAPC="$with_lua"
        PKG_CHECK_MODULES([LUA], $LUAPC >= 5.1, [
          AC_DEFINE([HAVE_LUA], [1], [liblua])
          AC_DEFINE([HAVE_LUA_H], [1], [lua.h])
          with_lua=yes
        ])
    ])
    AC_MSG_CHECKING([for chosen LUA])
    AC_MSG_RESULT([$LUAPC])
  ])
])
