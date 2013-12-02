AM_CPPFLAGS=@THREADFLAGS@ $(BOOST_CPPFLAGS)
lib_LTLIBRARIES = liblmdbbackend.la
#if !ALLSTATIC
#install-exec-local:
#	install .lib/liblmdbbackend.so.0.0.0 @libdir@
#endif

EXTRA_DIST=OBJECTFILES OBJECTLIBS

INCLUDES=@LMDB_CFLAGS@

liblmdbbackend_la_SOURCES=lmdbbackend.cc lmdbbackend.hh
liblmdbbackend_la_LDFLAGS=-module -avoid-version @LMDB_LIBS@

