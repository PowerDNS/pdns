AM_CPPFLAGS=$(PGSQL_inc) $(THREADFLAGS) $(BOOST_CPPFLAGS)
pkglib_LTLIBRARIES = libgpgsqlbackend.la

EXTRA_DIST=OBJECTFILES OBJECTLIBS \
	schema.pgsql.sql 

dist_doc_DATA=schema.pgsql.sql 

libgpgsqlbackend_la_SOURCES=gpgsqlbackend.cc gpgsqlbackend.hh \
	spgsql.hh spgsql.cc

libgpgsqlbackend_la_LDFLAGS=-module -avoid-version $(PGSQL_lib)
libgpgsqlbackend_la_LIBADD=-lssl $(LIBCRYPT) -lcrypto
