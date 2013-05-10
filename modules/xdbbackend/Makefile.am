AM_CPPFLAGS=@THREADFLAGS@
EXTRA_DIST=OBJECTFILES OBJECTLIBS
bin_PROGRAMS=xdb-fill

lib_LTLIBRARIES = libxdbbackend.la

libxdbbackend_la_SOURCES=xdbbackend.cc xtdb.cc xtdb.hh xdb.hh xgdbm.hh
libxdbbackend_la_LDFLAGS=-module -avoid-version -ltdb
libxdbbackend_la_CXXFLAGS = $(AM_CXXFLAGS)

xdb_fill_SOURCES=xdb-fill.cc xtdb.cc xtdb.hh
xdb_fill_LDFLAGS=-ltdb
