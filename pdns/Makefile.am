
AM_CXXFLAGS=-DSYSCONFDIR=\"@sysconfdir@\" -DLIBDIR=\"@libdir@\" -DLOCALSTATEDIR=\"@socketdir@\" @THREADFLAGS@ $(LUA_CFLAGS) $(SQLITE3_CFLAGS) $(POLARSSL_CFLAGS) -Iext/rapidjson/include -Iext/yahttp

AM_LFLAGS = -s -i
AM_YFLAGS = -d --verbose --debug

AM_CPPFLAGS=$(BOOST_CPPFLAGS) @THREADFLAGS@
if BOTAN110
AM_CPPFLAGS += $(BOTAN110_CFLAGS)
endif

if BOTAN18
AM_CPPFLAGS += $(BOTAN18_CFLAGS)
endif

EXTRA_DIST = dnslabeltext.rl dnslabeltext.cc mtasker.cc inflighter.cc docs/pdns_control.8  \
	docs/pdns_server.8 docs/zone2sql.8 docs/zone2ldap.8 docs/pdnssec.8 \
	docs/dnsreplay.8 docs/dnsscope.8 docs/dnswasher.8 docs/pdnssec.8 docs/zone2ldap.8 \
	bind-dnssec.schema.sqlite3.sql bindparser.h

SUBDIRS= $(POLARSSL_SUBDIR) ext/yahttp

BUILT_SOURCES=bind-dnssec.schema.sqlite3.sql.h version_generated.h bindparser.h
CLEANFILES=version_generated.h

noinst_SCRIPTS = pdns
sysconf_DATA = pdns.conf-dist 

sbin_PROGRAMS = pdns_server 
bin_PROGRAMS = pdns_control pdnssec zone2sql zone2ldap zone2json

if TOOLS
  bin_PROGRAMS += dnsbulktest dnsreplay dnsscan dnsscope dnstcpbench dnswasher nproxy dnsdist nsec3dig
endif

EXTRA_PROGRAMS=pdns_recursor sdig dnstcpbench dnsdist tsig-tests speedtest pdns_control dnsscope dnsgram rec_control \
testrunner dnsreplay \
toysdig dnsdemog dnswasher dnsscan nproxy notify pdnssec dnsbulktest nsec3dig

pdns_server_SOURCES=dnspacket.cc nameserver.cc tcpreceiver.hh \
qtype.cc logger.cc arguments.cc packethandler.cc tcpreceiver.cc \
packetcache.cc statbag.cc pdnsexception.hh arguments.hh distributor.hh \
dns.hh dnsbackend.hh dnsbackend.cc dnspacket.hh dynmessenger.hh lock.hh logger.hh \
nameserver.hh packetcache.hh packethandler.hh qtype.hh statbag.hh \
ueberbackend.hh pdns.conf-dist ws.hh ws.cc webserver.cc webserver.hh \
session.cc session.hh misc.cc misc.hh receiver.cc ueberbackend.cc \
dynlistener.cc dynlistener.hh  dynhandler.cc dynhandler.hh  \
resolver.hh resolver.cc slavecommunicator.cc mastercommunicator.cc communicator.cc communicator.hh dnsproxy.cc \
dnsproxy.hh unix_utility.cc common_startup.cc \
utility.hh iputils.hh common_startup.hh unix_semaphore.cc \
bind-dnssec.schema.sqlite3.sql.h \
bindparser.cc bindlexer.c \
backends/gsql/gsqlbackend.cc \
backends/gsql/gsqlbackend.hh backends/gsql/ssql.hh \
base64.cc sillyrecords.cc \
base64.hh zoneparser-tng.cc dnsrecords.cc dnswriter.cc \
rcpgenerator.cc	dnsparser.cc dns_random.hh dns_random.cc\
randomhelper.cc namespaces.hh nsecrecords.cc base32.cc dbdnsseckeeper.cc dnssecinfra.cc \
dnsseckeeper.hh dnssecinfra.hh base32.hh dns.cc dnssecsigner.cc polarrsakeyinfra.cc \
sha.hh md5.hh signingpipe.cc signingpipe.hh dnslabeltext.cc lua-pdns.cc lua-auth.cc lua-auth.hh serialtweaker.cc \
ednssubnet.cc ednssubnet.hh cachecleaner.hh json.cc json.hh \
version.hh version.cc rfc2136handler.cc responsestats.cc responsestats.hh


pdns_server_LDFLAGS=@moduleobjects@ @modulelibs@ @DYNLINKFLAGS@ @LIBDL@ @THREADFLAGS@  $(BOOST_SERIALIZATION_LDFLAGS) -rdynamic
pdns_server_LDADD= $(POLARSSL_LIBS) $(BOOST_SERIALIZATION_LIBS) $(LUA_LIBS) $(SQLITE3_LIBS) -Lext/yahttp/yahttp -lyahttp

if BOTAN110
pdns_server_SOURCES += botan110signers.cc botansigners.cc
pdns_server_LDADD += $(BOTAN110_LIBS) -lgmp -lrt
endif

if BOTAN18
pdns_server_SOURCES += botan18signers.cc botansigners.cc
pdns_server_LDADD += $(BOTAN18_LIBS) -lgmp
endif

if CRYPTOPP
pdns_server_SOURCES += cryptoppsigners.cc
pdns_server_LDADD += -lcryptopp
endif

if SQLITE3
pdns_server_SOURCES += ssqlite3.cc ssqlite3.hh
endif

if ORACLE
pdns_server_LDADD += $(ORACLE_LIBS)
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

pdnssec_LDFLAGS=@moduleobjects@ @modulelibs@ @DYNLINKFLAGS@ @LIBDL@ @THREADFLAGS@ $(BOOST_PROGRAM_OPTIONS_LDFLAGS) $(BOOST_SERIALIZATION_LDFLAGS) 
pdnssec_LDADD= $(POLARSSL_LIBS) $(BOOST_PROGRAM_OPTIONS_LIBS) $(BOOST_SERIALIZATION_LIBS) $(SQLITE3_LIBS)

zone2sql_SOURCES=bindparser.yy bindlexer.l bind-dnssec.schema.sqlite3.sql.h \
	arguments.cc logger.cc zone2sql.cc statbag.cc misc.cc \
	unix_utility.cc qtype.cc dns.cc \
	zoneparser-tng.cc dnsrecords.cc sillyrecords.cc \
	dnswriter.cc dnslabeltext.cc rcpgenerator.cc dnsparser.cc base64.cc \
	nsecrecords.cc dnssecinfra.cc base32.cc bindparserclasses.hh \
	dns_random.cc

zone2sql_LDFLAGS=@THREADFLAGS@
zone2sql_LDADD= $(POLARSSL_LIBS)

zone2json_SOURCES=bindparser.yy bindlexer.l bind-dnssec.schema.sqlite3.sql.h \
	arguments.cc logger.cc zone2json.cc statbag.cc misc.cc \
	unix_utility.cc qtype.cc zoneparser-tng.cc dnsrecords.cc \
	dnswriter.cc dnslabeltext.cc rcpgenerator.cc dnsparser.cc base64.cc sillyrecords.cc \
	nsecrecords.cc dnssecinfra.cc base32.cc bindparserclasses.hh

zone2json_LDFLAGS=@THREADFLAGS@
zone2json_LDADD= $(POLARSSL_LIBS)

zone2ldap_SOURCES=bindparser.yy bindlexer.l bind-dnssec.schema.sqlite3.sql.h \
	arguments.cc logger.cc zone2ldap.cc statbag.cc misc.cc \
	unix_utility.cc qtype.cc zoneparser-tng.cc dnsrecords.cc \
	dnswriter.cc dnslabeltext.cc rcpgenerator.cc dnsparser.cc base64.cc sillyrecords.cc \
	nsecrecords.cc dnssecinfra.cc base32.cc bindparserclasses.hh \
	dns_random.cc

zone2ldap_LDFLAGS=@THREADFLAGS@
zone2ldap_LDADD= $(POLARSSL_LIBS)

if BOTAN110
pdnssec_SOURCES += botan110signers.cc botansigners.cc
pdnssec_LDADD += $(BOTAN110_LIBS) -lgmp -lrt
endif

if BOTAN18
pdnssec_SOURCES += botan18signers.cc botansigners.cc
pdnssec_LDADD += $(BOTAN18_LIBS) -lgmp
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

sdig_SOURCES=sdig.cc sstuff.hh dnsparser.cc dnsparser.hh dnsrecords.cc dnswriter.cc dnslabeltext.cc dnswriter.hh \
	misc.cc misc.hh rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh unix_utility.cc \
	logger.cc statbag.cc qtype.cc sillyrecords.cc nsecrecords.cc base32.cc

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


speedtest_SOURCES=speedtest.cc dnsparser.cc dnsparser.hh dnsrecords.cc dnswriter.cc dnslabeltext.cc dnswriter.hh \
	misc.cc misc.hh rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh unix_utility.cc \
	qtype.cc sillyrecords.cc logger.cc statbag.cc nsecrecords.cc base32.cc 

dnswasher_SOURCES=dnswasher.cc misc.cc unix_utility.cc qtype.cc \
	logger.cc statbag.cc  dnspcap.cc dnspcap.hh dnsparser.hh 

dnswasher_LDFLAGS= @DYNLINKFLAGS@ @THREADFLAGS@

dnsbulktest_SOURCES=dnsbulktest.cc misc.cc unix_utility.cc qtype.cc logger.cc statbag.cc dnsparser.cc \
	dnsrecords.cc dnswriter.cc dnslabeltext.cc rcpgenerator.cc base32.cc base64.cc sillyrecords.cc nsecrecords.cc 
dnsbulktest_LDFLAGS= @DYNLINKFLAGS@ @THREADFLAGS@ $(BOOST_PROGRAM_OPTIONS_LDFLAGS)
dnsbulktest_LDADD= $(BOOST_PROGRAM_OPTIONS_LIBS)


dnsscan_SOURCES=dnsscan.cc misc.cc  qtype.cc anadns.hh \
	logger.cc statbag.cc  dnspcap.cc dnspcap.hh dnsparser.cc dnsrecords.cc dnsparser.hh  \
	rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh dnswriter.cc dnslabeltext.cc dnswriter.hh \
	unix_utility.cc utility.hh sillyrecords.cc nsecrecords.cc base32.cc

dnsreplay_SOURCES=dnsreplay.cc misc.cc  qtype.cc anadns.hh \
	logger.cc statbag.cc  dnspcap.cc dnspcap.hh dnsparser.cc dnsrecords.cc dnsparser.hh  \
	rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh dnswriter.cc dnslabeltext.cc dnswriter.hh \
	unix_utility.cc utility.hh sillyrecords.cc nsecrecords.cc base32.cc

dnsreplay_LDFLAGS= @DYNLINKFLAGS@ @THREADFLAGS@ $(BOOST_PROGRAM_OPTIONS_LDFLAGS)
dnsreplay_LDADD= $(BOOST_PROGRAM_OPTIONS_LIBS)

nproxy_SOURCES=nproxy.cc dnsparser.cc dnsrecords.cc dnsparser.hh  \
	rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh dnswriter.cc dnslabeltext.cc dnswriter.hh \
	sillyrecords.cc selectmplexer.cc   mplexer.hh misc.cc nsecrecords.cc  unix_utility.cc qtype.cc \
	logger.cc statbag.cc base32.cc

nproxy_LDFLAGS= @DYNLINKFLAGS@ @THREADFLAGS@ $(BOOST_PROGRAM_OPTIONS_LDFLAGS)
nproxy_LDADD= $(BOOST_PROGRAM_OPTIONS_LIBS)

notify_SOURCES=notify.cc dnsparser.cc dnsrecords.cc dnsparser.hh  \
	rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh dnswriter.cc dnslabeltext.cc dnswriter.hh \
	sillyrecords.cc selectmplexer.cc nsecrecords.cc base32.cc misc.cc unix_utility.cc \
	logger.cc qtype.cc statbag.cc

notify_LDFLAGS= @DYNLINKFLAGS@ @THREADFLAGS@ $(BOOST_PROGRAM_OPTIONS_LDFLAGS)
notify_LDADD= $(BOOST_PROGRAM_OPTIONS_LIBS)

dnsscope_SOURCES=dnsscope.cc misc.cc unix_utility.cc qtype.cc \
	logger.cc statbag.cc  dnspcap.cc dnspcap.hh dnsparser.cc dnsrecords.cc \
	base64.cc base64.hh dnswriter.cc dnslabeltext.cc dnswriter.hh rcpgenerator.cc rcpgenerator.hh \
	utility.hh dnsparser.hh sillyrecords.cc nsecrecords.cc base32.cc

dnsscope_LDFLAGS= @DYNLINKFLAGS@ @THREADFLAGS@ $(BOOST_PROGRAM_OPTIONS_LDFLAGS) 
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
        test-sha_hh.cc nameserver.cc misc.cc \
	unix_utility.cc logger.cc statbag.cc arguments.cc qtype.cc dnspacket.cc \
	dnswriter.cc base64.cc base32.cc dnsrecords.cc dnslabeltext.cc dnsparser.cc \
	rcpgenerator.cc ednssubnet.cc nsecrecords.cc sillyrecords.cc dnssecinfra.cc \
	test-base64_cc.cc test-iputils_hh.cc test-dns_random_hh.cc dns_random.cc \
	test-rcpgenerator_cc.cc responsestats.cc

testrunner_LDFLAGS= @DYNLINKFLAGS@ @THREADFLAGS@ $(BOOST_UNIT_TEST_FRAMEWORK_LDFLAGS)
testrunner_LDADD= $(POLARSSL_LIBS) $(BOOST_UNIT_TEST_FRAMEWORK_LIBS)

pdns_recursor_SOURCES=syncres.cc resolver.hh misc.cc unix_utility.cc qtype.cc \
logger.cc statbag.cc arguments.cc  lwres.cc pdns_recursor.cc reczones.cc lwres.hh \
mtasker.hh syncres.hh recursor_cache.cc recursor_cache.hh dnsparser.cc \
dnswriter.cc dnslabeltext.cc dnswriter.hh dnsrecords.cc dnsrecords.hh rcpgenerator.cc rcpgenerator.hh \
base64.cc base64.hh zoneparser-tng.cc zoneparser-tng.hh rec_channel.cc rec_channel.hh \
rec_channel_rec.cc selectmplexer.cc epollmplexer.cc sillyrecords.cc htimer.cc htimer.hh \
dns_random.cc \
lua-pdns.cc lua-pdns.hh lua-recursor.cc lua-recursor.hh randomhelper.cc  \
recpacketcache.cc recpacketcache.hh dns.cc nsecrecords.cc base32.cc cachecleaner.hh json_ws.cc json_ws.hh \
json.cc json.hh version.hh version.cc

pdns_recursor_LDFLAGS= $(LUA_LIBS)
pdns_recursor_LDADD= $(POLARSSL_LIBS)

pdns_control_SOURCES=dynloader.cc dynmessenger.cc  arguments.cc logger.cc statbag.cc \
misc.cc unix_utility.cc qtype.cc

pdns_control_LDFLAGS=@THREADFLAGS@

TESTS_ENVIRONMENT = env BOOST_TEST_LOG_LEVEL=message
TESTS=testrunner

dnslabeltext.cc: dnslabeltext.rl
	ragel dnslabeltext.rl -o dnslabeltext.cc

bind-dnssec.schema.sqlite3.sql.h: bind-dnssec.schema.sqlite3.sql
	( echo 'static char sqlCreate[] __attribute__((unused))=' ; sed 's/$$/"/g' bind-dnssec.schema.sqlite3.sql | sed 's/^/"/g'  ; echo ';' ) > $@

# for bindparser.h/hh
.hh.h:
	cp $< $@

build_date=$(shell LC_TIME=C date '+%Y%m%d%H%M%S')
build_host=$(shell id -u -n)@$(shell hostname -f)
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
	echo '#ifndef VERSION_GENERATED_H' > $@
	echo '#define VERSION_GENERATED_H' >> $@
	echo '#define PDNS_VERSION "$(pdns_version)"' >> $@
	echo '#define DIST_HOST "$(dist_host)"' >> $@
	echo '#define BUILD_DATE "$(build_date)"' >> $@
	echo '#define BUILD_HOST "$(build_host)"' >> $@
	echo '#endif //!VERSION_GENERATED_H' >> $@
