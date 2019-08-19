AM_CPPFLAGS += $(CASSANDRA_CFLAGS)

pkglib_LTLIBRARIES = libcassandrabackend.la

EXTRA_DIST = OBJECTFILES OBJECTLIBS

libcassandrabackend_la_SOURCES = cassandrabackend.cc cassandradnssec.cc cassandrafactory.cc
libcassandrabackend_la_LDFLAGS = -module -avoid-version
libcassandrabackend_la_LIBADD = $(CASSANDRA_LIBS)
