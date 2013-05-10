AM_CPPFLAGS=@THREADFLAGS@ $(BOOST_CPPFLAGS) $(LIBCURL_CFLAGS) -I../../pdns/ext/rapidjson/include
#if !ALLSTATIC
#install-exec-local:
#       install .lib/libremotebackend.so.0.0.0 @libdir@
#endif

EXTRA_DIST=OBJECTFILES OBJECTLIBS
lib_LTLIBRARIES = libremotebackend.la

libremotebackend_la_SOURCES=remotebackend.hh remotebackend.cc unixconnector.cc httpconnector.cc pipeconnector.cc

libremotebackend_la_LDFLAGS=-module -avoid-version
libremotebackend_la_LIBS=$(LIBCURL_LIBS)
