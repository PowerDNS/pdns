AM_CPPFLAGS=@THREADFLAGS@ $(BOOST_CPPFLAGS)
#if !ALLSTATIC
#install-exec-local:
#       install .lib/libremotebackend.so.0.0.0 @libdir@
#endif

EXTRA_DIST=OBJECTFILES OBJECTLIBS
lib_LTLIBRARIES = libremotebackend.la

libremotebackend_la_SOURCES=remotebackend.hh remotebackend.cc unixconnector.cc httpconnector.cc pipeconnector.cc 

libremotebackend_la_LDFLAGS=-module -avoid-version
libremotebackend_la_LIBS=-lboost_system -ljsoncpp -lcurl
