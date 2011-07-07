AM_CPPFLAGS=@THREADFLAGS@
lib_LTLIBRARIES = libgsqlite3backend.la

EXTRA_DIST=OBJECTFILES OBJECTLIBS

INCLUDES=-I@SQLITE3_CFLAGS@

libgsqlite3backend_la_SOURCES=gsqlite3backend.cc gsqlite3backend.hh \
                ssqlite3.hh ssqlite3.cc


libgsqlite3backend_la_LDFLAGS=-module -avoid-version -lsqlite3
