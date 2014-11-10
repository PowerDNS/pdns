AC_DEFUN([PDNS_CHECK_OPENDBX], [
  PKG_CHECK_MODULES([OPENDBX], [opendbx], [], [
    AC_CHECK_HEADERS([odbx.h], [
      AC_CHECK_LIB([opendbx], [odbx_init],
        [OPENDBX_LIBS="-lopendbx"],
        [AC_MSG_ERROR([libopendbx not found])]
      )], [
      AC_MSG_ERROR([opendbx header (odbx.h) not found])
      ]
    )
  ])
  AC_SUBST([OPENDBX_LIBS])
])

