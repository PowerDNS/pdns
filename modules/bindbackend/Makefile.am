pkglib_LTLIBRARIES = libbindbackend.la
AM_CPPFLAGS += -I../../pdns $(LIBCRYPTO_INCLUDES)

AM_LFLAGS = -i
AM_YFLAGS = -d --verbose --debug

BUILT_SOURCES = \
	../../pdns/bindlexer.l \
	../../pdns/bindparser.yy

dist_doc_DATA = \
	../../pdns/bind-dnssec.4.2.0_to_4.3.0_schema.sqlite3.sql \
	../../pdns/bind-dnssec.schema.sqlite3.sql

EXTRA_DIST = \
	OBJECTFILES \
	OBJECTLIBS \
	meson.build

libbindbackend_la_SOURCES = \
	bindbackend2.cc bindbackend2.hh \
	binddnssec.cc

if BINDBACKEND_DYNMODULE
libbindbackend_la_LDFLAGS = -module -avoid-version
else
libbindbackend_la_LDFLAGS = -static -avoid-version
endif
