AM_CPPFLAGS += $(UNIXODBC_CFLAGS)
pkglib_LTLIBRARIES = libgodbcbackend.la

EXTRA_DIST=OBJECTFILES OBJECTLIBS

dist_doc_DATA=schema.mssql.sql

libgodbcbackend_la_SOURCES=godbcbackend.cc godbcbackend.hh \
                sodbc.hh sodbc.cc

libgodbcbackend_la_LDFLAGS=-module -avoid-version
libgodbcbackend_la_LIBADD=$(UNIXODBC_LIBS)
