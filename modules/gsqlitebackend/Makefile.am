lib_LTLIBRARIES = libgsqlitebackend.la

EXTRA_DIST=OBJECTFILES OBJECTLIBS

INCLUDES=-I@SQLITE_incdir@

libgsqlitebackend_la_SOURCES=gsqlitebackend.cc gsqlitebackend.hh \
                ssqlite.hh ssqlite.cc


libgsqlitebackend_la_LDFLAGS=-module -lsqlite
