AM_CPPFLAGS=$(ORACLE_CFLAGS) @THREADFLAGS@
lib_LTLIBRARIES = libgoraclebackend.la

EXTRA_DIST=OBJECTFILES OBJECTLIBS

libgoraclebackend_la_SOURCES=goraclebackend.cc goraclebackend.hh \
    soracle.hh soracle.cc

libgoraclebackend_la_LDFLAGS=-module -avoid-version $(ORACLE_LIBS)
