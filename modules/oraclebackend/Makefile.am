AM_CPPFLAGS=$(ORACLE_CFLAGS) $(THREADFLAGS) $(BOOST_CPPFLAGS)

pkglib_LTLIBRARIES = liboraclebackend.la

EXTRA_DIST=OBJECTFILES OBJECTLIBS schema.oracle.sql drop-schema.oracle.sql

dist_doc_DATA=schema.oracle.sql drop-schema.oracle.sql

liboraclebackend_la_SOURCES=oraclebackend.cc oraclebackend.hh
liboraclebackend_la_LDFLAGS=-module -avoid-version $(ORACLE_LIBS)
liboraclebackend_la_LIBADD=-lclntsh
