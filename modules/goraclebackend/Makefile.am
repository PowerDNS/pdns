AM_CPPFLAGS += $(ORACLE_CFLAGS)

pkglib_LTLIBRARIES = libgoraclebackend.la

EXTRA_DIST = \
	OBJECTFILES \
	OBJECTLIBS \
	drop-schema.goracle.sql \
	schema.goracle.sql

dist_doc_DATA = \
	drop-schema.goracle.sql \
	schema.goracle.sql

libgoraclebackend_la_SOURCES = \
	goraclebackend.cc goraclebackend.hh \
	soracle.cc soracle.hh

libgoraclebackend_la_LDFLAGS = -module -avoid-version
libgoraclebackend_la_LIBADD = $(ORACLE_LIBS)
