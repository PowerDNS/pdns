AM_CPPFLAGS=@THREADFLAGS@
lib_LTLIBRARIES = libgodbcbackend.la

EXTRA_DIST=OBJECTFILES OBJECTLIBS

INCLUDES=-I@UNIXODBC_incdir@

libgodbcbackend_la_SOURCES=godbcbackend.cc godbcbackend.hh \
                sodbc.hh sodbc.cc


libgodbcbackend_la_LDFLAGS=-module -avoid-version -lodbc
