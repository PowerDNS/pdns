pkglib_LTLIBRARIES = libopendbxbackend.la

EXTRA_DIST = OBJECTFILES OBJECTLIBS

libopendbxbackend_la_SOURCES = \
	odbxbackend.cc odbxbackend.hh \
	odbxprivate.cc

libopendbxbackend_la_LDFLAGS = -module -avoid-version
libopendbxbackend_la_LIBADD = $(OPENDBX_LIBS)
