AM_CPPFLAGS += -I$(srcdir)/cassdriver/include -fPIC

pkglib_LTLIBRARIES = libcassandrabackend.la

#EXTRA_DIST = OBJECTFILES OBJECTLIBS

libcassandrabackend_la_SOURCES = cassandrabackend.cc cassandradnssec.cc cassandrafactory.cc
libcassandrabackend_la_LDFLAGS = -module -avoid-version -L${srcdir}/cassdriver/build/ -lcassandra_static -luv
