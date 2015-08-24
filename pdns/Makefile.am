AM_CXXFLAGS += -DSYSCONFDIR=\"$(sysconfdir)\" -DPKGLIBDIR=\"$(pkglibdir)\" -DLOCALSTATEDIR=\"$(socketdir)\" $(THREADFLAGS) $(LUA_CFLAGS) $(SQLITE3_CFLAGS) $(POLARSSL_CFLAGS) -I$(top_srcdir)/pdns/ext/rapidjson/include -I$(top_srcdir)/pdns/ext/yahttp

YAHTTP_LIBS = -Lext/yahttp/yahttp -lyahttp

AM_LFLAGS = -i
AM_YFLAGS = -d --verbose --debug

AM_CPPFLAGS=$(BOOST_CPPFLAGS) $(THREADFLAGS)
if BOTAN110
AM_CPPFLAGS += $(BOTAN110_CFLAGS)
endif

if BOTAN18
AM_CPPFLAGS += $(BOTAN18_CFLAGS)
endif

if PKCS11
AM_CPPFLAGS += $(P11KIT1_CFLAGS)
endif

EXTRA_DIST = dnslabeltext.rl dnslabeltext.cc mtasker.cc inflighter.cc docs/pdns_control.1  \
	docs/pdns_server.1 docs/zone2sql.1 docs/zone2ldap.1 docs/pdnssec.1 \
	docs/dnsreplay.1 docs/dnsscope.1 docs/dnswasher.1 docs/pdnssec.1 docs/zone2ldap.1 \
	bind-dnssec.schema.sqlite3.sql bindparser.h named.conf.parsertest

SUBDIRS= ext

BUILT_SOURCES=bind-dnssec.schema.sqlite3.sql.h version_generated.h bindparser.h
CLEANFILES=version_generated.h

noinst_SCRIPTS = pdns
sysconf_DATA = pdns.conf-dist 

sbin_PROGRAMS = pdns_server 
bin_PROGRAMS = pdns_control pdnssec zone2sql zone2ldap zone2json

if TOOLS
  bin_PROGRAMS += dnsbulktest dnsreplay dnsscan dnsscope dnstcpbench dnswasher nproxy nsec3dig saxfr
endif

EXTRA_PROGRAMS=pdns_recursor sdig saxfr dnstcpbench dnsdist tsig-tests speedtest dnsscope dnsgram rec_control \
testrunner dnsreplay zone2lmdb \
toysdig dnsdemog dnswasher dnsscan nproxy notify dnsbulktest nsec3dig saxfr

pdns_server_SOURCES=dnspacket.cc nameserver.cc tcpreceiver.hh \
qtype.cc logger.cc arguments.cc packethandler.cc tcpreceiver.cc \
packetcache.cc statbag.cc pdnsexception.hh arguments.hh distributor.hh \
dns.hh dnsbackend.hh dnsbackend.cc dnspacket.hh dynmessenger.hh lock.hh logger.hh \
nameserver.hh packetcache.hh packethandler.hh qtype.hh statbag.hh \
ueberbackend.hh pdns.conf-dist \
ws-auth.hh ws-auth.cc ws-api.cc ws-api.hh webserver.cc webserver.hh \
misc.cc misc.hh receiver.cc ueberbackend.cc \
dynlistener.cc dynlistener.hh  dynhandler.cc dynhandler.hh  \
resolver.hh resolver.cc slavecommunicator.cc mastercommunicator.cc communicator.cc communicator.hh dnsproxy.cc \
dnsproxy.hh unix_utility.cc common_startup.cc \
utility.hh iputils.hh common_startup.hh unix_semaphore.cc \
bind-dnssec.schema.sqlite3.sql.h \
bindparser.cc bindlexer.c \
backends/gsql/gsqlbackend.cc \
backends/gsql/gsqlbackend.hh backends/gsql/ssql.hh \
base64.cc sillyrecords.cc secpoll-auth.cc secpoll-auth.hh \
base64.hh zoneparser-tng.cc dnsrecords.cc dnswriter.cc \
rcpgenerator.cc	dnsparser.cc dns_random.hh dns_random.cc\
randomhelper.cc namespaces.hh nsecrecords.cc base32.cc dbdnsseckeeper.cc dnssecinfra.cc \
dnsseckeeper.hh dnssecinfra.hh base32.hh dns.cc dnssecsigner.cc polarrsakeyinfra.cc \
sha.hh md5.hh signingpipe.cc signingpipe.hh dnslabeltext.cc lua-pdns.cc lua-auth.cc lua-auth.hh serialtweaker.cc \
ednssubnet.cc ednssubnet.hh cachecleaner.hh json.cc json.hh \
version.hh version.cc rfc2136handler.cc responsestats.cc responsestats.hh \
comment.hh auth-carbon.cc


pdns_server_LDFLAGS=@moduleobjects@ @modulelibs@ $(DYNLINKFLAGS) @LIBDL@ $(THREADFLAGS)  $(BOOST_SERIALIZATION_LDFLAGS) -rdynamic
pdns_server_LDADD= $(POLARSSL_LIBS) $(BOOST_SERIALIZATION_LIBS) $(LUA_LIBS) $(SQLITE3_LIBS) $(YAHTTP_LIBS)

if BOTAN110
pdns_server_SOURCES += botan110signers.cc botansigners.cc
pdns_server_LDADD += $(BOTAN110_LIBS)
endif

if BOTAN18
pdns_server_SOURCES += botan18signers.cc botansigners.cc
pdns_server_LDADD += $(BOTAN18_LIBS)
endif

if CRYPTOPP
pdns_server_SOURCES += cryptoppsigners.cc
pdns_server_LDADD += $(CRYPTOPP_LIBS)
endif

if SQLITE3
pdns_server_SOURCES += ssqlite3.cc ssqlite3.hh
endif

if ORACLE
pdns_server_LDADD += $(ORACLE_LIBS)
endif

if PKCS11
pdns_server_SOURCES += pkcs11signers.cc pkcs11signers.hh
pdns_server_LDADD += $(P11KIT1_LIBS)
endif

pdnssec_SOURCES=pdnssec.cc dbdnsseckeeper.cc sstuff.hh dnsparser.cc dnsparser.hh dnsrecords.cc dnswriter.cc dnswriter.hh \
        misc.cc misc.hh rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh unix_utility.cc \
	logger.cc statbag.cc qtype.cc sillyrecords.cc nsecrecords.cc dnssecinfra.cc dnssecinfra.hh \
        base32.cc  ueberbackend.cc dnsbackend.cc arguments.cc packetcache.cc dnspacket.cc  \
	bindparser.cc bindlexer.c \
	backends/gsql/gsqlbackend.cc \
	backends/gsql/gsqlbackend.hh backends/gsql/ssql.hh zoneparser-tng.cc \
	dynlistener.cc dns.cc dnssecsigner.cc polarrsakeyinfra.cc \
	signingpipe.cc dnslabeltext.cc ednssubnet.cc cachecleaner.hh \
	dns_random.cc json.cc \
	serialtweaker.cc randomhelper.cc

pdnssec_LDFLAGS=@moduleobjects@ @modulelibs@ $(DYNLINKFLAGS) @LIBDL@ $(THREADFLAGS) $(BOOST_PROGRAM_OPTIONS_LDFLAGS) $(BOOST_SERIALIZATION_LDFLAGS) 
pdnssec_LDADD= $(POLARSSL_LIBS) $(BOOST_PROGRAM_OPTIONS_LIBS) $(BOOST_SERIALIZATION_LIBS) $(SQLITE3_LIBS) $(YAHTTP_LIBS)

zone2sql_SOURCES=bindparser.yy bindlexer.l bind-dnssec.schema.sqlite3.sql.h \
	arguments.cc logger.cc zone2sql.cc statbag.cc misc.cc \
	unix_utility.cc qtype.cc dns.cc \
	zoneparser-tng.cc dnsrecords.cc sillyrecords.cc \
	dnswriter.cc dnslabeltext.cc rcpgenerator.cc dnsparser.cc base64.cc \
	nsecrecords.cc base32.cc bindparserclasses.hh \
	dns_random.cc json.cc json.hh

zone2sql_LDFLAGS=$(THREADFLAGS)
zone2sql_LDADD= $(POLARSSL_LIBS)

zone2json_SOURCES=bindparser.yy bindlexer.l bind-dnssec.schema.sqlite3.sql.h \
	arguments.cc logger.cc zone2json.cc statbag.cc misc.cc \
	unix_utility.cc qtype.cc zoneparser-tng.cc dnsrecords.cc \
	dnswriter.cc dnslabeltext.cc rcpgenerator.cc dnsparser.cc base64.cc sillyrecords.cc \
	nsecrecords.cc base32.cc bindparserclasses.hh

zone2json_LDFLAGS=$(THREADFLAGS)
zone2json_LDADD= $(POLARSSL_LIBS)

zone2ldap_SOURCES=bindparser.yy bindlexer.l bind-dnssec.schema.sqlite3.sql.h \
	arguments.cc logger.cc zone2ldap.cc statbag.cc misc.cc \
	unix_utility.cc qtype.cc zoneparser-tng.cc dnsrecords.cc \
	dnswriter.cc dnslabeltext.cc rcpgenerator.cc dnsparser.cc base64.cc sillyrecords.cc \
	nsecrecords.cc base32.cc bindparserclasses.hh \
	dns_random.cc

zone2ldap_LDFLAGS=$(THREADFLAGS)
zone2ldap_LDADD= $(POLARSSL_LIBS)

if LMDB
bin_PROGRAMS += zone2lmdb

zone2lmdb_SOURCES=bindparser.yy bindlexer.l bind-dnssec.schema.sqlite3.sql.h \
	arguments.cc logger.cc zone2lmdb.cc statbag.cc misc.cc \
	unix_utility.cc qtype.cc zoneparser-tng.cc dnsrecords.cc \
	dnswriter.cc dnslabeltext.cc rcpgenerator.cc dnsparser.cc base64.cc sillyrecords.cc \
	nsecrecords.cc base32.cc bindparserclasses.hh \
	dns_random.cc dns.cc

zone2lmdb_LDFLAGS=$(THREADFLAGS)
zone2lmdb_LDADD= $(POLARSSL_LIBS) -llmdb
endif

if BOTAN110
pdnssec_SOURCES += botan110signers.cc botansigners.cc
pdnssec_LDADD += $(BOTAN110_LIBS)
endif

if BOTAN18
pdnssec_SOURCES += botan18signers.cc botansigners.cc
pdnssec_LDADD += $(BOTAN18_LIBS)
endif

if CRYPTOPP
pdnssec_SOURCES += cryptoppsigners.cc
pdnssec_LDADD += -lcryptopp
endif

if SQLITE3
pdnssec_SOURCES += ssqlite3.cc ssqlite3.hh
endif

if ORACLE
pdnssec_LDADD += $(ORACLE_LIBS)
endif

if PKCS11
pdnssec_SOURCES +=  pkcs11signers.cc pkcs11signers.hh
pdnssec_LDADD += $(P11KIT1_LIBS)
endif

sdig_SOURCES=sdig.cc sstuff.hh dnsparser.cc dnsparser.hh dnsrecords.cc dnswriter.cc dnslabeltext.cc dnswriter.hh \
	misc.cc misc.hh rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh unix_utility.cc \
	logger.cc statbag.cc qtype.cc sillyrecords.cc nsecrecords.cc base32.cc

saxfr_SOURCES=saxfr.cc sstuff.hh dnsparser.cc dnsparser.hh dnsrecords.cc dnswriter.cc dnslabeltext.cc dnswriter.hh \
	misc.cc misc.hh rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh unix_utility.cc \
	logger.cc statbag.cc qtype.cc sillyrecords.cc nsecrecords.cc base32.cc dnssecinfra.cc 
saxfr_LDADD= $(POLARSSL_LIBS)

if PKCS11
saxfr_SOURCES +=  pkcs11signers.cc pkcs11signers.hh
saxfr_LDADD += $(P11KIT1_LIBS)
endif

dnstcpbench_SOURCES=dnstcpbench.cc sstuff.hh dnsparser.cc dnsparser.hh dnsrecords.cc dnswriter.cc dnslabeltext.cc dnswriter.hh \
	misc.cc misc.hh rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh unix_utility.cc \
	logger.cc statbag.cc qtype.cc sillyrecords.cc nsecrecords.cc base32.cc
dnstcpbench_LDFLAGS=$(BOOST_PROGRAM_OPTIONS_LDFLAGS)
dnstcpbench_LDADD=$(BOOST_PROGRAM_OPTIONS_LIBS)


dnsdist_SOURCES=dnsdist.cc sstuff.hh dnsparser.cc dnsparser.hh dnsrecords.cc dnswriter.cc dnslabeltext.cc dnswriter.hh \
	misc.cc misc.hh rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh unix_utility.cc \
	logger.cc statbag.cc qtype.cc sillyrecords.cc nsecrecords.cc base32.cc iputils.cc
dnsdist_LDFLAGS=$(BOOST_PROGRAM_OPTIONS_LDFLAGS)
dnsdist_LDADD=$(BOOST_PROGRAM_OPTIONS_LIBS)


nsec3dig_SOURCES=nsec3dig.cc sstuff.hh dnsparser.cc dnsparser.hh dnsrecords.cc dnswriter.cc dnslabeltext.cc \
    dnswriter.hh dnssecinfra.cc \
	misc.cc misc.hh rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh unix_utility.cc \
	logger.cc statbag.cc qtype.cc sillyrecords.cc nsecrecords.cc base32.cc
nsec3dig_LDADD= $(POLARSSL_LIBS)

if PKCS11
nsec3dig_SOURCES +=  pkcs11signers.cc pkcs11signers.hh
nsec3dig_LDADD += $(P11KIT1_LIBS)
endif

toysdig_SOURCES=toysdig.cc sstuff.hh dnsparser.cc dnsparser.hh dnsrecords.cc dnswriter.cc dnslabeltext.cc dnswriter.hh \
	misc.cc misc.hh rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh unix_utility.cc \
	logger.cc statbag.cc qtype.cc sillyrecords.cc nsecrecords.cc base32.cc \
	ednssubnet.cc ednssubnet.hh dns_random.cc randomhelper.cc 
toysdig_LDADD= $(POLARSSL_LIBS)


tsig_tests_SOURCES=tsig-tests.cc sstuff.hh dnsparser.cc dnsparser.hh dnsrecords.cc dnswriter.cc dnslabeltext.cc dnswriter.hh \
	misc.cc misc.hh rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh unix_utility.cc \
	logger.cc statbag.cc qtype.cc sillyrecords.cc nsecrecords.cc base32.cc \
	dnssecinfra.cc resolver.cc arguments.cc dns_random.hh dns_random.cc \
	randomhelper.cc dns.cc
tsig_tests_LDADD= $(POLARSSL_LIBS)


if PKCS11
tsig_tests_SOURCES +=  pkcs11signers.cc pkcs11signers.hh
tsig_tests_LDADD += $(P11KIT1_LIBS)
endif

speedtest_SOURCES=speedtest.cc dnsparser.cc dnsparser.hh dnsrecords.cc dnswriter.cc dnslabeltext.cc dnswriter.hh \
	misc.cc misc.hh rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh unix_utility.cc \
	qtype.cc sillyrecords.cc logger.cc statbag.cc nsecrecords.cc base32.cc 

dnswasher_SOURCES=dnswasher.cc misc.cc unix_utility.cc qtype.cc \
	logger.cc statbag.cc  dnspcap.cc dnspcap.hh dnsparser.hh 

dnswasher_LDFLAGS= $(DYNLINKFLAGS) $(THREADFLAGS)

dnsbulktest_SOURCES=dnsbulktest.cc misc.cc unix_utility.cc qtype.cc logger.cc statbag.cc dnsparser.cc \
	dnsrecords.cc dnswriter.cc dnslabeltext.cc rcpgenerator.cc base32.cc base64.cc sillyrecords.cc nsecrecords.cc 
dnsbulktest_LDFLAGS= $(DYNLINKFLAGS) $(THREADFLAGS) $(BOOST_PROGRAM_OPTIONS_LDFLAGS)
dnsbulktest_LDADD= $(BOOST_PROGRAM_OPTIONS_LIBS)


dnsscan_SOURCES=dnsscan.cc misc.cc  qtype.cc anadns.hh \
	logger.cc statbag.cc  dnspcap.cc dnspcap.hh dnsparser.cc dnsrecords.cc dnsparser.hh  \
	rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh dnswriter.cc dnslabeltext.cc dnswriter.hh \
	unix_utility.cc utility.hh sillyrecords.cc nsecrecords.cc base32.cc

dnsreplay_SOURCES=dnsreplay.cc misc.cc  qtype.cc anadns.hh \
	logger.cc statbag.cc  dnspcap.cc dnspcap.hh dnsparser.cc dnsrecords.cc dnsparser.hh  \
	rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh dnswriter.cc dnslabeltext.cc dnswriter.hh \
	unix_utility.cc utility.hh sillyrecords.cc nsecrecords.cc base32.cc

dnsreplay_LDFLAGS= $(DYNLINKFLAGS) $(THREADFLAGS) $(BOOST_PROGRAM_OPTIONS_LDFLAGS)
dnsreplay_LDADD= $(BOOST_PROGRAM_OPTIONS_LIBS)

nproxy_SOURCES=nproxy.cc dnsparser.cc dnsrecords.cc dnsparser.hh  \
	rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh dnswriter.cc dnslabeltext.cc dnswriter.hh \
	sillyrecords.cc selectmplexer.cc   mplexer.hh misc.cc nsecrecords.cc  unix_utility.cc qtype.cc \
	logger.cc statbag.cc base32.cc

nproxy_LDFLAGS= $(DYNLINKFLAGS) $(THREADFLAGS) $(BOOST_PROGRAM_OPTIONS_LDFLAGS)
nproxy_LDADD= $(BOOST_PROGRAM_OPTIONS_LIBS)

notify_SOURCES=notify.cc dnsparser.cc dnsrecords.cc dnsparser.hh  \
	rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh dnswriter.cc dnslabeltext.cc dnswriter.hh \
	sillyrecords.cc selectmplexer.cc nsecrecords.cc base32.cc misc.cc unix_utility.cc \
	logger.cc qtype.cc statbag.cc dns.cc arguments.cc

notify_LDFLAGS= $(DYNLINKFLAGS) $(THREADFLAGS) $(BOOST_PROGRAM_OPTIONS_LDFLAGS)
notify_LDADD= $(BOOST_PROGRAM_OPTIONS_LIBS)

dnsscope_SOURCES=dnsscope.cc misc.cc unix_utility.cc qtype.cc \
	logger.cc statbag.cc  dnspcap.cc dnspcap.hh dnsparser.cc dnsrecords.cc \
	base64.cc base64.hh dnswriter.cc dnslabeltext.cc dnswriter.hh rcpgenerator.cc rcpgenerator.hh \
	utility.hh dnsparser.hh sillyrecords.cc nsecrecords.cc base32.cc dns.cc arguments.cc

dnsscope_LDFLAGS= $(DYNLINKFLAGS) $(THREADFLAGS) $(BOOST_PROGRAM_OPTIONS_LDFLAGS) 
dnsscope_LDADD = $(BOOST_PROGRAM_OPTIONS_LIBS) 

dnsgram_SOURCES=dnsgram.cc misc.cc unix_utility.cc qtype.cc \
	logger.cc statbag.cc  dnspcap.cc dnspcap.hh dnsparser.cc dnsrecords.cc \
	base64.cc base64.hh dnswriter.cc dnslabeltext.cc dnswriter.hh rcpgenerator.cc rcpgenerator.hh \
	utility.hh dnsparser.hh sillyrecords.cc nsecrecords.cc base32.cc

dnsdemog_SOURCES=dnsdemog.cc misc.cc unix_utility.cc qtype.cc \
	logger.cc statbag.cc  dnspcap.cc dnspcap.hh dnsparser.cc dnsrecords.cc \
	base64.cc base64.hh dnswriter.cc dnslabeltext.cc dnswriter.hh rcpgenerator.cc rcpgenerator.hh \
	utility.hh dnsparser.hh sillyrecords.cc nsecrecords.cc base32.cc

rec_control_SOURCES=rec_channel.cc rec_channel.hh rec_control.cc arguments.cc arguments.hh misc.cc qtype.cc \
	unix_utility.cc logger.cc statbag.cc

testrunner_SOURCES=testrunner.cc test-misc_hh.cc test-nameserver_cc.cc test-dnsrecords_cc.cc test-base32_cc.cc test-md5_hh.cc \
        packetcache.cc test-sha_hh.cc nameserver.cc test-packetcache_cc.cc misc.cc \
	unix_utility.cc logger.cc statbag.cc arguments.cc qtype.cc dnspacket.cc \
	dnswriter.cc base64.cc base32.cc dnsrecords.cc dnslabeltext.cc dnsparser.cc \
	rcpgenerator.cc ednssubnet.cc nsecrecords.cc sillyrecords.cc dnssecinfra.cc \
	test-base64_cc.cc test-iputils_hh.cc test-dns_random_hh.cc dns_random.cc \
	test-rcpgenerator_cc.cc responsestats.cc test-bindparser_cc.cc test-statbag_cc.cc \
	bindparser.cc bindlexer.c test-zoneparser_tng_cc.cc zoneparser-tng.hh \
        zoneparser-tng.cc dns.cc

testrunner_LDFLAGS= $(DYNLINKFLAGS) $(THREADFLAGS) $(BOOST_UNIT_TEST_FRAMEWORK_LDFLAGS)
testrunner_LDADD= $(POLARSSL_LIBS) $(BOOST_UNIT_TEST_FRAMEWORK_LIBS)

if PKCS11
testrunner_SOURCES += pkcs11signers.cc pkcs11signers.hh
testrunner_LDADD += $(P11KIT1_LIBS)
endif

pdns_recursor_SOURCES=syncres.cc resolver.hh misc.cc unix_utility.cc qtype.cc \
logger.cc statbag.cc arguments.cc  lwres.cc pdns_recursor.cc reczones.cc lwres.hh \
mtasker.hh syncres.hh recursor_cache.cc recursor_cache.hh dnsparser.cc \
dnswriter.cc dnslabeltext.cc dnswriter.hh dnsrecords.cc dnsrecords.hh rcpgenerator.cc rcpgenerator.hh \
base64.cc base64.hh zoneparser-tng.cc zoneparser-tng.hh rec_channel.cc rec_channel.hh \
rec_channel_rec.cc selectmplexer.cc epollmplexer.cc sillyrecords.cc htimer.cc htimer.hh \
dns_random.cc \
lua-pdns.cc lua-pdns.hh lua-recursor.cc lua-recursor.hh randomhelper.cc  \
recpacketcache.cc recpacketcache.hh dns.cc nsecrecords.cc base32.cc cachecleaner.hh \
ws-recursor.cc ws-recursor.hh ws-api.cc ws-api.hh webserver.cc webserver.hh \
json.cc json.hh version.hh version.cc responsestats.cc rec-carbon.cc ext/yahttp/yahttp/reqresp.cpp \
ext/yahttp/yahttp/router.cpp

pdns_recursor_LDFLAGS= $(LUA_LIBS)
pdns_recursor_LDADD= $(POLARSSL_LIBS) $(YAHTTP_LIBS)

pdns_control_SOURCES=dynloader.cc dynmessenger.cc  arguments.cc logger.cc statbag.cc \
misc.cc unix_utility.cc qtype.cc

pdns_control_LDFLAGS=$(THREADFLAGS)

if UNIT_TESTS
TESTS_ENVIRONMENT = env BOOST_TEST_LOG_LEVEL=message
TESTS=testrunner
else
check-local:
	@echo "Unit tests are not enabled"
	@echo "Run ./configure --enable-unit-tests"
endif

dnslabeltext.cc: dnslabeltext.rl
	ragel dnslabeltext.rl -o dnslabeltext.cc

bind-dnssec.schema.sqlite3.sql.h: bind-dnssec.schema.sqlite3.sql
	( echo 'static char sqlCreate[] __attribute__((unused))=' ; sed 's/$$/"/g' bind-dnssec.schema.sqlite3.sql | sed 's/^/"/g'  ; echo ';' ) > $@

# for bindparser.h/hh
.hh.h:
	cp $< $@

build_date=$(shell LC_TIME=C date '+%Y%m%d%H%M%S')
build_host=$(shell id -u -n)@$(shell hostname -f 2>/dev/null || hostname 2>/dev/null || echo localhost)
if RELEASE_BUILD
pdns_version=$(PACKAGE_VERSION)
dist_host=$(DIST_HOST)
else
git_version=$(shell git describe --always --dirty=+ 2>/dev/null)
# Do the test in shell, so we don't confuse automake with ifeq/ifneq.
pdns_version=$(shell test -z "$(git_version)" && echo UNKNOWN || echo "git-$(git_version)")
dist_host=$(build_host)
endif

version.o: version_generated.h

.PHONY: version_generated.h
version_generated.h:
	@echo '#ifndef VERSION_GENERATED_H' > $@
	@echo '#define VERSION_GENERATED_H' >> $@
	@echo '#define PDNS_VERSION "$(pdns_version)"' >> $@
	@echo '#define DIST_HOST "$(dist_host)"' >> $@
	@echo '#define BUILD_DATE "$(build_date)"' >> $@
	@echo '#define BUILD_HOST "$(build_host)"' >> $@
	@echo '#endif //!VERSION_GENERATED_H' >> $@
