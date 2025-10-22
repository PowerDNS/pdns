AC_DEFUN([PDNS_CHECK_AARCH64_UINT64X2_T], [
  AC_CANONICAL_BUILD()
  AS_IF([test "$build_cpu" = "aarch64"], [
    AC_MSG_CHECKING([whether the compiler supports calculations with uint64x2_t])
    AC_LANG_PUSH([C++])
    AC_COMPILE_IFELSE([AC_LANG_SOURCE([
#    if defined(_MSC_VER) && defined(_M_ARM64)
#        include <arm64_neon.h>
#    else
#        include <arm_neon.h>
#    endif
int main() {
  uint64x2_t foo = {0, 0};
  uint64x2_t bar = vshrq_n_u8(foo, 1);
  return 0;
}
    ])],[
    dnl We just define this. Proper detection is only done in Meson
    AC_DEFINE([HAVE_IPCRYPT2], [1], [Define to 1 to build with IPCrypt2])
    AC_MSG_RESULT([ok])
    ],[
    AC_MSG_FAILURE([no])
    ])
    AC_LANG_POP()
  ])
])
