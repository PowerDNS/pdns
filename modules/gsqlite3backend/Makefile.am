pkglib_LTLIBRARIES = libgsqlite3backend.la

EXTRA_DIST = \
	OBJECTFILES \
	OBJECTLIBS \
	dnssec-3.x_to_3.4.0_schema.sqlite3.sql \
	nodnssec-3.x_to_3.4.0_schema.sqlite3.sql \
	schema.sqlite3.sql

dist_doc_DATA = \
	dnssec-3.x_to_3.4.0_schema.sqlite3.sql \
	nodnssec-3.x_to_3.4.0_schema.sqlite3.sql \
	3.4.0_to_4.0.0_schema.sqlite3.sql \
	4.0.0_to_4.2.0_schema.sqlite3.sql \
	schema.sqlite3.sql

libgsqlite3backend_la_SOURCES = gsqlite3backend.cc gsqlite3backend.hh

libgsqlite3backend_la_LDFLAGS = -module -avoid-version
