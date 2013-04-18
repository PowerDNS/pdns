AM_CPPFLAGS=@CDB_CFLAGS@ @THREADFLAGS@
lib_LTLIBRARIES = libtinydnsbackend.la

EXTRA_DIST=OBJECTFILES OBJECTLIBS

libtinydnsbackend_la_SOURCES=cdb.cc cdb.hh tinydnsbackend.cc tinydnsbackend.hh
libtinydnsbackend_la_LDFLAGS=-module -avoid-version @CDB_LIBS@