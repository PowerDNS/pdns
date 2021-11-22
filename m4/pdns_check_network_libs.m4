AC_DEFUN([PDNS_CHECK_NETWORK_LIBS],[
  AC_SEARCH_LIBS([inet_aton], [resolv])
  AC_SEARCH_LIBS([gethostbyname], [nsl])
  AC_SEARCH_LIBS([socket], [socket])
  AC_SEARCH_LIBS([gethostent], [nsl])
  AC_CHECK_FUNCS([recvmmsg sendmmsg accept4])
  AC_CHECK_DECL(getifaddrs, [AC_DEFINE([HAVE_GETIFADDRS], [1], [Define to 1 if you have getifaddrs])], [], [#include <ifaddrs.h>])
])
