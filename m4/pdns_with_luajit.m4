AC_DEFUN([PDNS_WITH_LUAJIT],[
  AC_MSG_CHECKING([whether we will be linking in LuaJIT])
  AC_ARG_WITH([luajit],
    [AS_HELP_STRING([--with-luajit], [build LuaJIT bindings @<:@default=auto@:>@])],
    [with_luajit=$withval],
    [with_luajit=no]
  )
  AC_MSG_RESULT([$with_luajit])

  AS_IF([test "x$with_luajit" = "xyes"], [
    LUAJITPC="$with_luajit"
    PKG_CHECK_MODULES([LUA], [luajit],
      [AC_DEFINE([HAVE_LUA], [1], [Define to 1 if you have LuaJIT])],
      [LUAJITPC=""]
    )
    AS_IF([test "x$LUAJITPC" = "x"], [
      AC_MSG_ERROR([LuaJIT not found])]
    )
  ])

  AM_CONDITIONAL([LUA], [test "x$with_luajit" = "xyes"])
])
