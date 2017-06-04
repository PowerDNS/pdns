# initial test version of this Makefile.am (will be fully dyanamic soon!)
AM_CPPFLAGS=@THREADFLAGS@ $(BOOST_CPPFLAGS) -I /usr/include -I /usr/include/boost

EXTRA_DIST=OBJECTFILES OBJECTLIBS

lib_LTLIBRARIES=libgeosqlbackend.la
libgeosqlbackend_la_SOURCES=geosqlbackend.cpp geosqlbackend.h
libgeosqlbackend_la_LDFLAGS=-module -avoid-version 
libgeosqlbackend_la_LIBADD=-lopendbxplus -lboost_regex
