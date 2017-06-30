AC_DEFUN([PDNS_CHECK_PTHREAD_NP],[
  AC_SEARCH_LIBS([pthread_setaffinity_np], [pthread], [AC_DEFINE(HAVE_PTHREAD_SETAFFINITY_NP, [1], [Define to 1 if you have pthread_setaffinity_np])])
])
