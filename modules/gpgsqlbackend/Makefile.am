AM_CPPFLAGS=$(PGSQL_inc) $(THREADFLAGS) $(BOOST_CPPFLAGS)
pkglib_LTLIBRARIES = libgpgsqlbackend.la

EXTRA_DIST=OBJECTFILES OBJECTLIBS \
	schema.pgsql.sql nodnssec-3.x_to_3.4.0_schema.pgsql.sql \
	dnssec-3.x_to_3.4.0_schema.pgsql.sql

dist_doc_DATA=schema.pgsql.sql nodnssec-3.x_to_3.4.0_schema.pgsql.sql \
	dnssec-3.x_to_3.4.0_schema.pgsql.sql

libgpgsqlbackend_la_SOURCES=gpgsqlbackend.cc gpgsqlbackend.hh \
	spgsql.hh spgsql.cc

libgpgsqlbackend_la_LDFLAGS=-module -avoid-version $(PGSQL_lib)
libgpgsqlbackend_la_LIBADD=-lssl $(LIBCRYPT) -lcrypto
