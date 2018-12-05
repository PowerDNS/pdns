AC_DEFUN([PDNS_ENABLE_FUZZ_TARGETS], [
  AC_MSG_CHECKING([whether to enable fuzzing targets])
  AC_ARG_ENABLE([fuzz_targets],
    AS_HELP_STRING([--enable-fuzz-targets],
      [enable fuzz targets @<:@default=no@:>@]),
    [enable_fuzz_targets=$enableval],
    [enable_fuzz_targets=no]
  )
  AC_MSG_RESULT([$enable_fuzz_targets])
  AM_CONDITIONAL([FUZZ_TARGETS], [test "x$enable_fuzz_targets" != "xno"])
])
