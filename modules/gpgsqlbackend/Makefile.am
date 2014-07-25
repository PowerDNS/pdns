AM_CPPFLAGS=-I$(PGSQL_incdir) $(THREADFLAGS) $(BOOST_CPPFLAGS)
pkglib_LTLIBRARIES = libgpgsqlbackend.la

EXTRA_DIST=OBJECTFILES OBJECTLIBS \
	schema.pgsql.sql nodnssec-3.x_to_3.4.0_schema.pgsql.sql dnssec-3.x_to_3.4.0_schema.pgsql.sql

dist_doc_DATA=schema.pgsql.sql nodnssec-3.x_to_3.4.0_schema.pgsql.sql dnssec-3.x_to_3.4.0_schema.pgsql.sql

libgpgsqlbackend_la_SOURCES=gpgsqlbackend.cc gpgsqlbackend.hh \
	spgsql.hh spgsql.cc

## Filter out known build breakers for Mac OS X
## Don't remove the empty lines between if and endif or tabs will screw up your makefile
if OS_MACOSX

libgpgsqlbackend_la_LDFLAGS=-module -avoid-version $(PGSQL_lib) -lpq
else

libgpgsqlbackend_la_LDFLAGS=-module -avoid-version $(PGSQL_lib) -Wl,-Bstatic -lpq -Wl,-Bdynamic
endif

libgpgsqlbackend_la_LIBADD=-lssl $(LIBCRYPT) -lcrypto
