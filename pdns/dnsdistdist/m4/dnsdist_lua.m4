AC_DEFUN([DNSDIST_LUA],[
  AC_MSG_CHECKING([which version of Lua will be linked against])
  AC_ARG_WITH([lua],
    [AS_HELP_STRING([--with-lua], [Lua version to build against @<:@default=auto@:>@])],
    [with_lua=$withval],
    [with_lua=auto]
  )
  AC_MSG_RESULT([$with_lua])

  AS_IF([test "x$with_lua" != "xno"],[
    AS_IF([test "x$with_lua" = "xyes" -o "x$with_lua" = "xauto"],[
      for LUAPC in lua5.3 lua-5.3 lua53 lua5.2 lua-5.2 lua52 lua5.1 lua-5.1 lua51 lua; do
        PKG_CHECK_MODULES([LUA], $LUAPC >= 5.1, [
          AC_DEFINE([HAVE_LUA], [1], [Define to 1 if you have lua])
          with_lua=yes
        ],[
          LUAPC="" # otherwise pkg_check will fail
        ])
        if test "x$LUA_LIBS" != "x"; then break; fi
      done
    ],[
       LUAPC="$with_lua"
       PKG_CHECK_MODULES([LUA], $LUAPC >= 5.1, [
         AC_DEFINE([HAVE_LUA], [1], [Define to 1 if you have Lua])
         with_lua=yes
       ])
    ])
    AC_MSG_CHECKING([for chosen LUA])
    AS_IF([test "x$LUAPC" = "x"], [
      AC_MSG_ERROR([no Lua found])
      ],[
      AC_MSG_RESULT([$LUAPC])
    ])
  ],[
    AC_MSG_ERROR([Lua is not optional])
  ])
  AM_CONDITIONAL([LUA], [test "x$with_lua" = "xyes"])
])

