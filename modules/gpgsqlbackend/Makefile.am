AM_CPPFLAGS += $(PGSQL_CFLAGS)
pkglib_LTLIBRARIES = libgpgsqlbackend.la

EXTRA_DIST = \
	OBJECTFILES \
	OBJECTLIBS \
	3.4.0_to_4.1.0_schema.pgsql.sql \
	4.1.0_to_4.2.0_schema.pgsql.sql \
	4.2.0_to_4.3.0_schema.pgsql.sql \
	dnssec-3.x_to_3.4.0_schema.pgsql.sql \
	nodnssec-3.x_to_3.4.0_schema.pgsql.sql \
	schema.pgsql.sql

dist_doc_DATA = \
	schema.pgsql.sql \
	nodnssec-3.x_to_3.4.0_schema.pgsql.sql \
	dnssec-3.x_to_3.4.0_schema.pgsql.sql \
	3.4.0_to_4.1.0_schema.pgsql.sql \
	4.1.0_to_4.2.0_schema.pgsql.sql \
	4.2.0_to_4.3.0_schema.pgsql.sql

libgpgsqlbackend_la_SOURCES = \
	gpgsqlbackend.cc gpgsqlbackend.hh \
	spgsql.cc spgsql.hh

libgpgsqlbackend_la_LDFLAGS = -module -avoid-version
libgpgsqlbackend_la_LIBADD = $(PGSQL_LIBS)
