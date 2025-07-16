pkglib_LTLIBRARIES = libgsqlite3backend.la

AM_CPPFLAGS += $(LIBCRYPTO_INCLUDES)

EXTRA_DIST = \
	OBJECTFILES \
	OBJECTLIBS

dist_doc_DATA = \
	dnssec-3.x_to_3.4.0_schema.sqlite3.sql \
	nodnssec-3.x_to_3.4.0_schema.sqlite3.sql \
	3.4.0_to_4.0.0_schema.sqlite3.sql \
	4.0.0_to_4.2.0_schema.sqlite3.sql \
	4.2.0_to_4.3.0_schema.sqlite3.sql \
	4.3.0_to_4.3.1_schema.sqlite3.sql \
	4.3.1_to_4.7.0_schema.sqlite3.sql \
	schema.sqlite3.sql

libgsqlite3backend_la_SOURCES = gsqlite3backend.cc gsqlite3backend.hh

if GSQLITE3BACKEND_DYNMODULE
libgsqlite3backend_la_LDFLAGS = -module -avoid-version
else
libgsqlite3backend_la_LDFLAGS = -static -avoid-version
endif
