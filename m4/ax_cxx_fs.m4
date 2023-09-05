AC_DEFUN([AX_CXX_CXXFS], [
   AC_LANG_PUSH([C++])
   old_LIBS="$LIBS"
   dnl * Test first if it can be used without anything, then -lstdc++fs and -lc++fs
   AC_CACHE_CHECK([for library with std::filesystem], [ax_cxx_cv_filesystem_lib], [
      ax_cxx_cv_filesystem_lib=none
      AC_LINK_IFELSE([AC_LANG_PROGRAM(
        [[#include <iostream>
          #include <filesystem>]],
        [[std::filesystem::path path(".");
          std::filesystem::status(path);]])],
        [], [
           LIBS="$LIBS -lstdc++fs"
           AC_LINK_IFELSE([AC_LANG_PROGRAM(
             [[#include <iostream>
               #include <filesystem>]],
             [[std::filesystem::path path(".");
               std::filesystem::status(path);]])],
             [ax_cxx_cv_filesystem_lib=stdc++fs], [
               LIBS="$old_LIBS -lc++fs"
               AC_LINK_IFELSE([AC_LANG_PROGRAM(
                 [[#include <iostream>
                   #include <filesystem>]],
                 [[std::filesystem::path path(".");
                   std::filesystem::status(path);]])],
                 [ax_cxx_cv_filesystem_lib=c++fs], [AC_MSG_ERROR([Cannot find std::filesystem library])])
      ])])
      LIBS="$old_LIBS"
   ])
   AC_LANG_POP()
])
