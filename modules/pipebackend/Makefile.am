pkglib_LTLIBRARIES = libpipebackend.la

AM_CPPFLAGS += $(LIBCRYPTO_INCLUDES)

EXTRA_DIST = \
	OBJECTFILES \
	OBJECTLIBS \
	backend.pl

libpipebackend_la_SOURCES = \
	coprocess.cc coprocess.hh \
	pipebackend.cc pipebackend.hh

if PIPEBACKEND_DYNMODULE
libpipebackend_la_LDFLAGS = -module -avoid-version
else
libpipebackend_la_LDFLAGS = -static -avoid-version
endif

