AC_DEFUN([PDNS_CHECK_PTHREAD_NP],[
  AC_SEARCH_LIBS([pthread_setaffinity_np], [pthread], [AC_DEFINE(HAVE_PTHREAD_SETAFFINITY_NP, [1], [Define to 1 if you have pthread_setaffinity_np])])
  AC_SEARCH_LIBS([pthread_getattr_np], [pthread], [AC_DEFINE(HAVE_PTHREAD_GETATTR_NP, [1], [Define to 1 if you have pthread_getattr_np])])
  AC_SEARCH_LIBS([pthread_get_stackaddr_np], [pthread], [AC_DEFINE(HAVE_PTHREAD_GET_STACKADDR_NP, [1], [Define to 1 if you have pthread_get_stackaddr_np])])
  AC_SEARCH_LIBS([pthread_get_stacksize_np], [pthread], [AC_DEFINE(HAVE_PTHREAD_GET_STACKSIZE_NP, [1], [Define to 1 if you have pthread_get_stacksize_np])])
])
