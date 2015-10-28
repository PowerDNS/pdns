AC_DEFUN([PDNS_WITH_LUA],[
  AC_MSG_CHECKING([whether we will be linking in Lua])
  AC_ARG_WITH([lua],
    [AS_HELP_STRING([--with-lua], [build Lua Bindings @<:@default=auto@:>@])],
    [with_lua=$withval],
    [with_lua=auto]
  )
  AC_MSG_RESULT([$with_lua])

  AS_IF([test "x$with_lua" != "xno"],[
    AS_IF([test "x$with_lua" = "xyes" -o "x$with_lua" = "xauto"],
      [for LUAPC in lua5.3 lua-5.3 lua53 lua5.2 lua-5.2 lua52 lua5.1 lua-5.1 lua51 lua; do
         PKG_CHECK_MODULES([LUA], $LUAPC >= 5.1, [
           AC_DEFINE([HAVE_LUA], [1], [Define to 1 if you have lua])
           with_lua=yes
         ], [LUAPC=""]) # otherwise pkg_check will fail
         if test "x$LUA_LIBS" != "x"; then break; fi
       done
      ],
      [LUAPC="$with_lua"
        PKG_CHECK_MODULES([LUA], $LUAPC >= 5.1, [
          AC_DEFINE([HAVE_LUA], [1], [Define to 1 if you have lua])
          with_lua=yes
        ])
    ])
    AC_MSG_CHECKING([for chosen LUA])
    AS_IF([test "x$LUAPC" = "x"], [
      AS_IF([test "x$with_lua" = "xyes"],
        [AC_MSG_ERROR([cannot find lua])],
        [AC_MSG_RESULT([not found])]
      )],
      [AC_MSG_RESULT([$LUAPC])]
    )
  ])
  AM_CONDITIONAL([LUA], [test "x$with_lua" = "xyes"])
])
