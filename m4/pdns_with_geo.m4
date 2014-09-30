AC_DEFUN([PDNS_CHECK_GEOIP], [
  PKG_CHECK_MODULES([GEOIP], [geoip],[],
    AC_MSG_ERROR([Could not find libGeoIP])
  )
  PKG_CHECK_MODULES([YAML], [yaml-cpp >= 0.5],[],
    AC_MSG_ERROR([Could not find yaml-cpp])
  )
])
