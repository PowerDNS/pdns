
EXTRA_DIST=OBJECTFILES OBJECTLIBS 
bin_PROGRAMS=xdb-fill

lib_LTLIBRARIES = libxdbbackend.la

libxdbbackend_la_SOURCES=xdbbackend.cc xtdb.cc xtdb.hh xdb.hh xgdbm.hh
libxdbbackend_la_LDFLAGS=-module -ltdb

xdb_fill_SOURCES=xdb-fill.cc xtdb.cc xtdb.hh
xdb_fill_LDFLAGS=-ltdb