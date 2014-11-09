AC_DEFUN([PDNS_CHECK_OPENDBX], [
  AC_CHECK_HEADERS([odbx.h], [
    AC_CHECK_LIB([opendbx], [odbx_init],
      [LIBOPENDBX="opendbx"],
      [AC_MSG_ERROR([libopendbx not found])]
    )], [
    AC_MSG_ERROR([opendbx header (odbx.h) not found])
    ]
  )
  AC_SUBST([LIBOPENDBX])
])

