AM_CPPFLAGS=$(ORACLE_CFLAGS) $(THREADFLAGS) $(BOOST_CPPFLAGS)
pkglib_LTLIBRARIES = libgoraclebackend.la

EXTRA_DIST=OBJECTFILES OBJECTLIBS \
	schema.goracle.sql drop-schema.goracle.sql

dist_doc_DATA = schema.goracle.sql drop-schema.goracle.sql

libgoraclebackend_la_SOURCES=goraclebackend.cc goraclebackend.hh \
    soracle.hh soracle.cc

libgoraclebackend_la_LDFLAGS=-module -avoid-version $(ORACLE_LIBS)
