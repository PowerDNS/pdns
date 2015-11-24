dnl Check for support for LTO 

AC_DEFUN([AC_CC_LTO],[
    AC_REQUIRE([gl_UNKNOWN_WARNINGS_ARE_ERRORS])
    LTO_CFLAGS=
    OLD_CXXFLAGS=$CXXFLAGS
    CXXFLAGS="-flto"
    gl_COMPILER_OPTION_IF([-flto], [
       LTO_CFLAGS="-flto"
       ], [
          ],
          [AC_LANG_PROGRAM([[
#include <pthread.h>
__thread unsigned int t_id;
            ]], [[t_id = 1;]])]
        )
    CXXFLAGS=$OLD_CXXFLAGS
    AC_SUBST([LTO_CFLAGS])
])
