AC_DEFUN([PDNS_ENABLE_KISS], [
  AC_ARG_ENABLE([unsafe-rng-kiss],
    AS_HELP_STRING([--enable-unsafe-rng-kiss],
      [Enable unsafe rng KISS]), [
        AC_DEFINE([HAVE_KISS_RNG], [1], [Define to 1 to enable unsafe rng KISS])
  ])
])
