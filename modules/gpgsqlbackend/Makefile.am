AM_CPPFLAGS=@THREADFLAGS@
lib_LTLIBRARIES = libgpgsqlbackend.la

EXTRA_DIST=OBJECTFILES OBJECTLIBS
INCLUDES=-I@PGSQL_incdir@

libgpgsqlbackend_la_SOURCES=gpgsqlbackend.cc gpgsqlbackend.hh \
		spgsql.hh spgsql.cc

libgpgsqlbackend_la_LDFLAGS=-module -avoid-version @PGSQL_lib@ -Wl,-Bstatic -lpq \
	-Wl,-Bdynamic 

libgpgsqlbackend_la_LIBADD=-lssl @LIBCRYPT@ -lcrypto



