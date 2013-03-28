AM_CPPFLAGS=@THREADFLAGS@

lib_LTLIBRARIES = liboraclebackend.la

EXTRA_DIST=OBJECTFILES OBJECTLIBS schema.sql dropschema.sql

INCLUDES= $(ORACLE_CFLAGS)

liboraclebackend_la_SOURCES=oraclebackend.cc oraclebackend.hh
liboraclebackend_la_LDFLAGS=-module -avoid-version $(ORACLE_LIBS)
liboraclebackend_la_LIBADD=-lclntsh
