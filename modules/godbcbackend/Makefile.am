AM_CPPFLAGS=-I@UNIXODBC_incdir@ @THREADFLAGS@
lib_LTLIBRARIES = libgodbcbackend.la

EXTRA_DIST=OBJECTFILES OBJECTLIBS

libgodbcbackend_la_SOURCES=godbcbackend.cc godbcbackend.hh \
                sodbc.hh sodbc.cc


libgodbcbackend_la_LDFLAGS=-module -avoid-version -lodbc
