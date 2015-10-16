pkglib_LTLIBRARIES = libcassandrabackend.la

EXTRA_DIST = \
	OBJECTFILES \
	OBJECTLIBS 

libcassandrabackend_la_SOURCES = \
	backendrecord.h cassandratables.h backendutil.cc \
	cassandradbmanager.h cassandradbmanager.cc cassandrabackend.cc 

libcassandrabackend_la_LDFLAGS = -module -avoid-version
libcassandrabackend_la_LIBADD = $(CASSANDRA_LIBS)

