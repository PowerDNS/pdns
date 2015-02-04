AM_CPPFLAGS = @THREADFLAGS@ @BOOST_CPPFLAGS@ $(MYSQL_CFLAGS)
EXTRA_DIST= OBJECTFILES OBJECTLIBS
pkglib_LTLIBRARIES = libgeosqlbackend.la
libgeosqlbackend_la_SOURCES =geosqlbackend.cc geosqlbackend.hh
libgeosqlbackend_la_LDFLAGS =-module -avoid-version
libgeosqlbackend_la_LIBADD = @BOOST_REGEX_LDFLAGS@ $(MYSQL_LIBS)
