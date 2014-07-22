AM_CPPFLAGS=$(THREADFLAGS) $(BOOST_CPPFLAGS)

EXTRA_DIST = OBJECTFILES OBJECTLIBS

pkglib_LTLIBRARIES = libopendbxbackend.la
libopendbxbackend_la_SOURCES = odbxbackend.hh odbxbackend.cc odbxprivate.cc
libopendbxbackend_la_LDFLAGS =-module -avoid-version
libopendbxbackend_la_LIBADD =-l$(LIBOPENDBX)
