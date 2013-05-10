AM_CPPFLAGS=$(ORACLE_CFLAGS) @THREADFLAGS@
lib_LTLIBRARIES = libgoraclebackend.la
#bin_PROGRAMS = soracle

#soracle_SOURCES=soracle.cc soracle.hh

EXTRA_DIST=OBJECTFILES OBJECTLIBS

libgoraclebackend_la_SOURCES=goraclebackend.cc goraclebackend.hh \
		soracle.hh soracle.cc


libgoraclebackend_la_LDFLAGS=-module -avoid-version $(ORACLE_LIBS)
#soracle_LDFLAGS=-module  -L$(ORACLE_HOME)/lib -lclient9  -lclntst9 -ldl -pthread

#	-Wl,-Bstatic -lpq++ -lpq -Wl,-Bdynamic -lssl -lcrypt -lcrypto



