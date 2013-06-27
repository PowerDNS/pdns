AM_CPPFLAGS=@THREADFLAGS@

EXTRA_DIST=OBJECTFILES OBJECTLIBS

lib_LTLIBRARIES = librandombackend.la

librandombackend_la_SOURCES=randombackend.cc
librandombackend_la_CXXFLAGS=-I$(abs_top_srcdir)
librandombackend_la_LDFLAGS=-module -avoid-version
