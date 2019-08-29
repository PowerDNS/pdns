AM_CPPFLAGS += $(CDB_CFLAGS)

pkglib_LTLIBRARIES = libtinydnsbackend.la

EXTRA_DIST = OBJECTFILES OBJECTLIBS

libtinydnsbackend_la_SOURCES = \
	../../pdns/cdb.cc ../../pdns/cdb.hh \
	tinydnsbackend.cc tinydnsbackend.hh

libtinydnsbackend_la_LDFLAGS = -module -avoid-version
libtinydnsbackend_la_LIBADD = $(CDB_LIBS)
