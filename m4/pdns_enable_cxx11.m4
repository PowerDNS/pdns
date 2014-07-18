AC_DEFUN([PDNS_ENABLE_CXX11], [
  AC_ARG_ENABLE([c++11],
    [AS_HELP_STRING([--enable-c++11],[Enable C++11 compile @<:@default=no@:>@])],
    [enable_cxx11=$enableval],
    [enable_cxx11=no]
  )

  AS_IF([test "x$enable_cxx11" != "xno"], [
    AX_CXX_COMPILE_STDCXX_11([noext],[mandatory])
  ])
]) 
