AM_CPPFLAGS=@THREADFLAGS@ $(BOOST_CPPFLAGS)
#if !ALLSTATIC
#install-exec-local:
#	install .lib/libpipebackend.so.0.0.0 @libdir@
#endif

EXTRA_DIST=OBJECTFILES OBJECTLIBS backend.pl
lib_LTLIBRARIES = libpipebackend.la

libpipebackend_la_SOURCES=pipebackend.cc pipebackend.hh coprocess.cc coprocess.hh
libpipebackend_la_LDFLAGS=-module -avoid-version

