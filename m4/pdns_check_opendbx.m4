AC_DEFUN([PDNS_CHECK_OPENDBX],[
  AC_CHECK_HEADERS([odbx.h], , [AC_MSG_ERROR([opendbx header (odbx.h) not found])])
  AC_SUBST([LIBOPENDBX])
  AC_CHECK_LIB([opendbx], [odbx_init],
    [AC_DEFINE([HAVE_LIBOPENDBX], [], [Have -lopendbx])
     LIBOPENDBX="opendbx"
    ]
  )
])

