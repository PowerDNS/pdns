AC_DEFUN([PDNS_CHECK_PYTHON_VENV], [
  dnl Check for optional Python, at least version 3.6.
  AM_PATH_PYTHON([3.6],,[:])
  dnl Check for Python venv module
  AS_IF([test "${PYTHON}" != ":"], [
    AX_PYTHON_MODULE([venv],[])
  ])
  AM_CONDITIONAL([HAVE_VENV], [test "x${HAVE_PYMOD_VENV}" = "xyes"])
])
