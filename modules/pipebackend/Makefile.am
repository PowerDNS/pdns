pkglib_LTLIBRARIES = libpipebackend.la

AM_CPPFLAGS += $(LIBCRYPTO_INCLUDES)

EXTRA_DIST = \
	OBJECTFILES \
	OBJECTLIBS \
	backend.pl

libpipebackend_la_SOURCES = \
	coprocess.cc coprocess.hh \
	pipebackend.cc pipebackend.hh

libpipebackend_la_LDFLAGS = -module -avoid-version

