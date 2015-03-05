AM_CPPFLAGS=$(THREADFLAGS) $(BOOST_CPPFLAGS)
pkglib_LTLIBRARIES = liblmdbbackend.la

EXTRA_DIST = \
	lmdb-example.pl \
	OBJECTFILES \
	OBJECTLIBS

liblmdbbackend_la_SOURCES=lmdbbackend.cc lmdbbackend.hh
liblmdbbackend_la_LDFLAGS=-module -avoid-version
liblmdbbackend_la_LIBADD=-l$(LIBLMDB)
