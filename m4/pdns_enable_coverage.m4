AC_DEFUN([PDNS_ENABLE_COVERAGE], [
  AC_MSG_CHECKING([whether to enable code coverage])
  AC_ARG_ENABLE([coverage],
    AS_HELP_STRING([--enable-coverage],
      [enable code coverage @<:@default=no@:>@]),
    [enable_coverage=$enableval],
    [enable_coverage=no]
  )
  AC_MSG_RESULT([$enable_coverage])

  AS_IF([test "x$enable_coverage" = "xclang"], [
    dnl let's see if the clang++ specific format is supported,
    dnl as it has a much lower overhead and is more accurate,
    dnl see https://clang.llvm.org/docs/SourceBasedCodeCoverage.html
    gl_COMPILER_OPTION_IF([-fprofile-instr-generate -fcoverage-mapping], [
      CFLAGS="$CFLAGS -DCOVERAGE -DCLANG_COVERAGE -fprofile-instr-generate -fcoverage-mapping"
      CXXFLAGS="$CXXFLAGS -DCOVERAGE -DCLANG_COVERAGE -fprofile-instr-generate -fcoverage-mapping"
    ], [
      AC_MSG_ERROR([$CXX does not support gathering coverage data in the clang format])
    ])
   ])

  AS_IF([test "x$enable_coverage" = "xyes"], [
    gl_COMPILER_OPTION_IF([-fprofile-arcs -ftest-coverage], [
      CFLAGS="$CFLAGS -DCOVERAGE --coverage"
      CXXFLAGS="$CXXFLAGS -DCOVERAGE --coverage"
      LDFLAGS="$LDFLAGS --coverage"
    ], [
      AC_MSG_ERROR([$CXX does not support gathering coverage data])
    ])
  ])
])
