noinst_LTLIBRARIES = libbind2backend.la
AM_CPPFLAGS=-I../.. $(BOOST_CPPFLAGS) @THREADFLAGS@

BUILT_SOURCES=bind-dnssec.schema.sqlite3.sql.h bindparser.h

bind-dnssec.schema.sqlite3.sql.h: ../../bind-dnssec.schema.sqlite3.sql
	( echo 'static char sqlCreate[] __attribute__((unused))=' ; sed 's/$$/"/g' ../../bind-dnssec.schema.sqlite3.sql | sed 's/^/"/g'  ; echo ';' ) > $@


libbind2backend_la_SOURCES=bindbackend2.cc bindbackend2.hh bindparser.yy \
bindlexer.l ../../zoneparser-tng.cc ../../misc.cc  \
bindparserclasses.hh ../../unix_utility.cc binddnssec.cc bind-dnssec.schema.sqlite3.sql.h

libbind2backend_la_CXXFLAGS=$(AM_CXXFLAGS)
libbind2backend_la_CFLAGS=$(AM_CFLAGS)
libbind2backend_la_LDFLAGS=-module -avoid-version

bin_PROGRAMS = zone2sql zone2ldap zone2json

EXTRA_DIST=dnslabeltext.cc bindparser.cc bindparser.h bind-dnssec.schema.sqlite3.sql.h

zone2sql_SOURCES=bindparser.yy bindlexer.l bind-dnssec.schema.sqlite3.sql.h \
../../arguments.cc ../../logger.cc zone2sql.cc ../../statbag.cc ../../misc.cc \
../../unix_utility.cc ../../qtype.cc ../../dns.cc \
../../zoneparser-tng.cc ../../dnsrecords.cc ../../sillyrecords.cc \
../../dnswriter.cc dnslabeltext.cc ../../rcpgenerator.cc ../../dnsparser.cc ../../base64.cc \
../../nsecrecords.cc ../../dnssecinfra.cc  ../../base32.cc ../../md5.cc ../../aes/dns_random.cc \
../../aes/aescpp.h ../../aes/aescrypt.c ../../aes/aes.h ../../aes/aeskey.c ../../aes/aes_modes.c ../../aes/aesopt.h \
../../aes/aestab.c ../../aes/aestab.h ../../aes/brg_endian.h ../../aes/brg_types.h  # ../../dbdnsseckeeper.cc

zone2json_SOURCES=bindparser.yy bindlexer.l bind-dnssec.schema.sqlite3.sql.h \
../../arguments.cc ../../logger.cc zone2json.cc ../../statbag.cc ../../misc.cc \
../../unix_utility.cc ../../qtype.cc  ../../zoneparser-tng.cc ../../dnsrecords.cc \
../../dnswriter.cc dnslabeltext.cc  ../../rcpgenerator.cc ../../dnsparser.cc ../../base64.cc ../../sillyrecords.cc \
../../nsecrecords.cc ../../dnssecinfra.cc  ../../base32.cc ../../md5.cc

zone2ldap_SOURCES=bindparser.yy bindlexer.l bind-dnssec.schema.sqlite3.sql.h \
../../arguments.cc ../../logger.cc zone2ldap.cc ../../statbag.cc ../../misc.cc \
../../unix_utility.cc ../../qtype.cc  ../../zoneparser-tng.cc ../../dnsrecords.cc \
../../dnswriter.cc dnslabeltext.cc  ../../rcpgenerator.cc ../../dnsparser.cc ../../base64.cc ../../sillyrecords.cc \
../../nsecrecords.cc ../../dnssecinfra.cc  ../../base32.cc ../../md5.cc ../../aes/dns_random.cc \
../../aes/aescpp.h ../../aes/aescrypt.c ../../aes/aes.h ../../aes/aeskey.c ../../aes/aes_modes.c ../../aes/aesopt.h \
../../aes/aestab.c ../../aes/aestab.h ../../aes/brg_endian.h ../../aes/brg_types.h # ../../dbdnsseckeeper.cc

zone2ldap_LDFLAGS=@THREADFLAGS@
if HAVE_LIBPOLARSSL
zone2ldap_LDADD=
else
zone2ldap_LDADD= ../../ext/polarssl-1.1.2/library/libpolarssl.a
endif

zone2sql_LDFLAGS=@THREADFLAGS@
if HAVE_LIBPOLARSSL
zone2sql_LDADD=
else
zone2sql_LDADD= ../../ext/polarssl-1.1.2/library/libpolarssl.a 
endif

zone2json_LDFLAGS=@THREADFLAGS@
if HAVE_LIBPOLARSSL
zone2json_LDADD=
else
zone2json_LDADD= ../../ext/polarssl-1.1.2/library/libpolarssl.a
endif

AM_LFLAGS = -s -i
AM_YFLAGS = -d --verbose --debug

dnslabeltext.cc: ../../dnslabeltext.rl
	ragel ../../dnslabeltext.rl -o dnslabeltext.cc

.hh.h:
	cp $< $@
