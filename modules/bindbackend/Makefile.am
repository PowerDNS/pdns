pkglib_LTLIBRARIES = libbindbackend.la
AM_CPPFLAGS += -I../../pdns

AM_LFLAGS = -i
AM_YFLAGS = -d --verbose --debug

BUILT_SOURCES = \
	../../pdns/bind-dnssec.schema.sqlite3.sql.h \
	../../pdns/bindlexer.l \
	../../pdns/bindparser.yy

dist_doc_DATA = \
	../../pdns/bind-dnssec.4.2.0_to_4.3.0_schema.sqlite3.sql \
	../../pdns/bind-dnssec.schema.sqlite3.sql

EXTRA_DIST = OBJECTFILES OBJECTLIBS

libbindbackend_la_SOURCES = \
	bindbackend2.cc bindbackend2.hh \
	binddnssec.cc

libbindbackend_la_LDFLAGS = -module -avoid-version

../../pdns/bind-dnssec.schema.sqlite3.sql.h: ../../pdns/bind-dnssec.schema.sqlite3.sql
	( echo 'static char sqlCreate[] __attribute__((unused))=' ; sed 's/$$/"/g' $< | sed 's/^/"/g'  ; echo ';' ) > $@

# for bindparser.h/hh
.hh.h:
	cp $< $@
