pkglib_LTLIBRARIES = libpipebackend.la

AM_CPPFLAGS += $(LIBCRYPTO_INCLUDES)

EXTRA_DIST = \
	OBJECTFILES \
	OBJECTLIBS \
	backend.pl \
	backend-v3.pl \
	backend-v5.pl \
	meson.build

libpipebackend_la_SOURCES = \
	coprocess.cc coprocess.hh \
	pipebackend.cc pipebackend.hh

if PIPEBACKEND_DYNMODULE
libpipebackend_la_LDFLAGS = -module -avoid-version
else
libpipebackend_la_LDFLAGS = -static -avoid-version
endif

