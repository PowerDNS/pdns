AC_DEFUN([PDNS_ENABLE_SANITIZERS], [
  PDNS_ENABLE_ASAN
  PDNS_ENABLE_MSAN
  PDNS_ENABLE_TSAN
  PDNS_ENABLE_LSAN
  PDNS_ENABLE_UBSAN

  AS_IF([test "x$enable_asan" != "xno" -a "x$enable_tsan" != "xno"],[
    AC_MSG_ERROR([Address Sanitizer is not compatible with Thread Sanitizer])
  ])

  AS_IF([test "x$enable_msan" != "xno" -a "x$enable_asan" != "xno"],[
    AC_MSG_ERROR([Memory Sanitizer is not compatible with Address Sanitizer])
  ])

  AS_IF([test "x$enable_msan" != "xno" -a "x$enable_lsan" != "xno"],[
    AC_MSG_ERROR([Memory Sanitizer is not compatible with Leak Sanitizer])
  ])

  AS_IF([test "x$enable_msan" != "xno" -a "x$enable_tsan" != "xno"],[
    AC_MSG_ERROR([Memory Sanitizer is not compatible with Thread Sanitizer])
  ])

  AS_IF([test "x$enable_asan" != "xno" -o "x$enable_tsan" != "xno" -o "x$enable_lsan" != "xno" -o "x$enable_ubsan" != "xno" -o "x$enable_msan" != "xno"], [
    gl_WARN_ADD([-fno-omit-frame-pointer])
  ])
])

AC_DEFUN([PDNS_ENABLE_ASAN], [
  AC_REQUIRE([gl_UNKNOWN_WARNINGS_ARE_ERRORS])
  AC_MSG_CHECKING([whether to enable AddressSanitizer])
  AC_ARG_ENABLE([asan],
    AS_HELP_STRING([--enable-asan],
      [enable AddressSanitizer @<:@default=no@:>@]),
    [enable_asan=$enableval],
    [enable_asan=no]
  )
  AC_MSG_RESULT([$enable_asan])

  AS_IF([test "x$enable_asan" != "xno"], [
    gl_COMPILER_OPTION_IF([-fsanitize=address],
      [SANITIZER_FLAGS="-fsanitize=address $SANITIZER_FLAGS"],
      [AC_MSG_ERROR([Cannot enable AddressSanitizer])]
    )
  ])
  AC_SUBST([SANITIZER_FLAGS])
])

AC_DEFUN([PDNS_ENABLE_TSAN], [
  AC_REQUIRE([gl_UNKNOWN_WARNINGS_ARE_ERRORS])
  AC_MSG_CHECKING([whether to enable ThreadSanitizer])
  AC_ARG_ENABLE([tsan],
    AS_HELP_STRING([--enable-tsan],
      [enable ThreadSanitizer @<:@default=no@:>@]),
    [enable_tsan=$enableval],
    [enable_tsan=no]
  )
  AC_MSG_RESULT([$enable_tsan])

  AS_IF([test "x$enable_tsan" != "xno"], [
    gl_COMPILER_OPTION_IF([-fsanitize=thread],
      [SANITIZER_FLAGS="-fsanitize=thread $SANITIZER_FLAGS"],
      [AC_MSG_ERROR([Cannot enable ThreadSanitizer])]
    )
  ])
  AC_SUBST([SANITIZER_FLAGS])
])

AC_DEFUN([PDNS_ENABLE_LSAN], [
  AC_REQUIRE([gl_UNKNOWN_WARNINGS_ARE_ERRORS])
  AC_MSG_CHECKING([whether to enable LeakSanitizer])
  AC_ARG_ENABLE([lsan],
    AS_HELP_STRING([--enable-lsan],
      [enable LeakSanitizer @<:@default=no@:>@]),
    [enable_lsan=$enableval],
    [enable_lsan=no]
  )
  AC_MSG_RESULT([$enable_lsan])

  AS_IF([test "x$enable_lsan" != "xno"], [
    gl_COMPILER_OPTION_IF([-fsanitize=leak],
      [SANITIZER_FLAGS="-fsanitize=leak $SANITIZER_FLAGS"],
      [AC_MSG_ERROR([Cannot enable LeakSanitizer])]
    )
  ])
  AC_SUBST([SANITIZER_FLAGS])
])

AC_DEFUN([PDNS_ENABLE_UBSAN], [
  AC_REQUIRE([gl_UNKNOWN_WARNINGS_ARE_ERRORS])
  AC_MSG_CHECKING([whether to enable Undefined Behaviour Sanitizer])
  AC_ARG_ENABLE([ubsan],
    AS_HELP_STRING([--enable-ubsan],
      [enable Undefined Behaviour Sanitizer @<:@default=no@:>@]),
    [enable_ubsan=$enableval],
    [enable_ubsan=no]
  )
  AC_MSG_RESULT([$enable_ubsan])

  AS_IF([test "x$enable_ubsan" != "xno"], [
    gl_COMPILER_OPTION_IF([-fsanitize=undefined],
      [SANITIZER_FLAGS="-fsanitize=undefined $SANITIZER_FLAGS"],
      [AC_MSG_ERROR([Cannot enable Undefined Behaviour Sanitizer])]
    )
  ])
  AC_SUBST([SANITIZER_FLAGS])
])

AC_DEFUN([PDNS_ENABLE_MSAN], [
  AC_REQUIRE([gl_UNKNOWN_WARNINGS_ARE_ERRORS])
  AC_MSG_CHECKING([whether to enable MemorySanitizer])
  AC_ARG_ENABLE([msan],
    AS_HELP_STRING([--enable-msan],
      [enable MemorySanitizer @<:@default=no@:>@]),
    [enable_msan=$enableval],
    [enable_msan=no]
  )
  AC_MSG_RESULT([$enable_msan])

  AS_IF([test "x$enable_msan" != "xno"], [
    gl_COMPILER_OPTION_IF([-fsanitize=memory],
      [SANITIZER_FLAGS="-fsanitize=memory $SANITIZER_FLAGS"],
      [AC_MSG_ERROR([Cannot enable MemorySanitizer])]
    )
  ])
  AC_SUBST([SANITIZER_FLAGS])
])

