AM_CPPFLAGS += \
	$(LIBCRYPTO_CFLAGS)

AM_LDFLAGS = $(THREADFLAGS)

EXTRA_DIST = \
	OBJECTFILES\
	dlsobackend_api.h

pkglib_LTLIBRARIES = libdlsobackend.la

libdlsobackend_la_SOURCES = \
	dlsobackend.hh \
	dlsobackend.cc

libdlsobackend_la_LDFLAGS = -module -avoid-version
