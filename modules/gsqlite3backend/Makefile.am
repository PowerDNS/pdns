AM_CPPFLAGS=@THREADFLAGS@ $(BOOST_CPPFLAGS)
lib_LTLIBRARIES = libgsqlite3backend.la

EXTRA_DIST=OBJECTFILES OBJECTLIBS \
	dnssec.schema.sqlite3.sql extended.schema.sqlite3.sql no-dnssec.schema.sqlite3.sql

libgsqlite3backend_la_SOURCES=gsqlite3backend.cc gsqlite3backend.hh

libgsqlite3backend_la_LDFLAGS=-module -avoid-version
