AM_CPPFLAGS += $(MYSQL_CFLAGS)
pkglib_LTLIBRARIES = libmydnsbackend.la

EXTRA_DIST = \
	OBJECTFILES \
	OBJECTLIBS \
	schema.mydns.sql

dist_doc_DATA = schema.mydns.sql

libmydnsbackend_la_SOURCES = \
	mydnsbackend.cc mydnsbackend.hh

libmydnsbackend_la_LDFLAGS = -module -avoid-version
libmydnsbackend_la_LIBADD = \
	../gmysqlbackend/smysql.lo \
	$(MYSQL_LIBS)
