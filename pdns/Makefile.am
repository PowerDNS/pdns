AM_CPPFLAGS += \
	-I$(top_srcdir)/pdns/ext/rapidjson/include \
	$(YAHTTP_CFLAGS) \
	$(POLARSSL_CFLAGS)

AM_CXXFLAGS = \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DPKGLIBDIR=\"$(pkglibdir)\" \
	-DLOCALSTATEDIR=\"$(socketdir)\"

AM_LFLAGS = -i
AM_YFLAGS = -d --verbose --debug

if BOTAN110
AM_CPPFLAGS += $(BOTAN110_CFLAGS)
endif

if BOTAN18
AM_CPPFLAGS += $(BOTAN18_CFLAGS)
endif

if PKCS11
AM_CPPFLAGS += $(P11KIT1_CFLAGS)
endif

if SQLITE3
AM_CPPFLAGS += $(SQLITE3_CFLAGS)
endif

if LUA
AM_CPPFLAGS +=$(LUA_CFLAGS)
endif

EXTRA_DIST = \
	dnslabeltext.rl \
	dnslabeltext.cc \
	mtasker.cc \
	inflighter.cc \
	docs/pdns_control.8  \
	docs/pdns_server.8 \
	docs/zone2sql.8 \
	docs/zone2ldap.8 \
	docs/pdnssec.8 \
	docs/dnsreplay.8 \
	docs/dnsscope.8 \
	docs/dnswasher.8 \
	docs/pdnssec.8 \
	docs/zone2ldap.8 \
	bind-dnssec.schema.sqlite3.sql \
	bindparser.h \
	named.conf.parsertest \
	pdns.conf-dist

SUBDIRS = ext

BUILT_SOURCES = \
	bind-dnssec.schema.sqlite3.sql.h \
	version_generated.h \
	bindparser.h

CLEANFILES = version_generated.h

noinst_SCRIPTS = pdns.init
sysconf_DATA = pdns.conf-dist

sbin_PROGRAMS = pdns_server
bin_PROGRAMS = \
	pdns_control \
	pdnssec \
	zone2sql \
	zone2ldap \
	zone2json

if TOOLS
bin_PROGRAMS += \
	dnsbulktest \
	dnsreplay \
	dnsscan \
	dnsscope \
	dnstcpbench \
	dnswasher \
	dnsdist \
	notify \
	nproxy \
	nsec3dig \
	saxfr
endif

EXTRA_PROGRAMS = \
	dnsbulktest \
	dnsdemog \
	dnsdist \
	dnsgram \
	dnsreplay \
	dnsscan \
	dnsscope \
	dnstcpbench \
	dnswasher \
	notify \
	nproxy \
	nsec3dig \
	pdns_recursor \
	rec_control \
	saxfr \
	sdig \
	speedtest \
	testrunner \
	toysdig \
	tsig-tests \
	zone2lmdb

pdns_server_SOURCES = \
	arguments.cc arguments.hh \
	auth-carbon.cc \
	backends/gsql/gsqlbackend.cc backends/gsql/gsqlbackend.hh \
	backends/gsql/ssql.hh \
	base32.cc base32.hh \
	base64.cc base64.hh \
	bind-dnssec.schema.sqlite3.sql.h \
	bindlexer.l \
	bindparser.cc \
	cachecleaner.hh \
	comment.hh \
	common_startup.cc common_startup.hh \
	communicator.cc communicator.hh \
	dbdnsseckeeper.cc \
	distributor.hh \
	dns.cc dns.hh \
	dns_random.cc dns_random.hh \
	dnsbackend.cc dnsbackend.hh \
	dnslabeltext.cc \
	dnspacket.cc dnspacket.hh \
	dnsparser.cc \
	dnsproxy.cc dnsproxy.hh \
	dnsrecords.cc \
	dnssecinfra.cc dnssecinfra.hh \
	dnsseckeeper.hh \
	dnssecsigner.cc \
	dnswriter.cc \
	dynhandler.cc dynhandler.hh \
	dynlistener.cc dynlistener.hh \
	dynmessenger.hh \
	ednssubnet.cc ednssubnet.hh \
	iputils.hh \
	json.cc json.hh \
	lock.hh \
	logger.cc logger.hh \
	lua-auth.cc lua-auth.hh \
	lua-pdns.cc \
	mastercommunicator.cc \
	md5.hh \
	misc.cc misc.hh \
	nameserver.cc nameserver.hh \
	namespaces.hh \
	nsecrecords.cc \
	packetcache.cc packetcache.hh \
	packethandler.cc packethandler.hh \
	pdnsexception.hh \
	polarrsakeyinfra.cc \
	qtype.cc qtype.hh \
	randomhelper.cc \
	rcpgenerator.cc	\
	receiver.cc \
	resolver.cc resolver.hh \
	responsestats.cc responsestats.hh \
	rfc2136handler.cc \
	secpoll-auth.cc secpoll-auth.hh \
	serialtweaker.cc \
	sha.hh \
	signingpipe.cc signingpipe.hh \
	sillyrecords.cc \
	slavecommunicator.cc \
	statbag.cc statbag.hh \
	tcpreceiver.cc tcpreceiver.hh \
	ueberbackend.cc ueberbackend.hh \
	unix_semaphore.cc \
	unix_utility.cc \
	utility.hh \
	version.cc version.hh \
	webserver.cc webserver.hh \
	ws-api.cc ws-api.hh \
	ws-auth.cc ws-auth.hh \
	zoneparser-tng.cc


pdns_server_LDFLAGS = \
	$(DYNLINKFLAGS) \
	$(THREADFLAGS) \
	$(BOOST_SERIALIZATION_LDFLAGS) \
	-rdynamic

pdns_server_LDADD = \
	@moduleobjects@ \
	@modulelibs@ \
	$(LIBDL) \
	$(POLARSSL_LIBS) \
	$(BOOST_SERIALIZATION_LIBS) \
	$(YAHTTP_LIBS)

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
pdns_server_LDADD += $(CRYPTOPP_LIBS)
endif

if SQLITE3
pdns_server_SOURCES += ssqlite3.cc ssqlite3.hh
pdns_server_LDADD += $(SQLITE3_LIBS)
endif

if ORACLE
pdns_server_LDADD += $(ORACLE_LIBS)
endif

if PKCS11
pdns_server_SOURCES += pkcs11signers.cc pkcs11signers.hh
pdns_server_LDADD += $(P11KIT1_LIBS)
endif

if LUA
pdns_server_LDADD += $(LUA_LIBS)
endif

pdnssec_SOURCES = \
	arguments.cc \
	backends/gsql/gsqlbackend.cc backends/gsql/gsqlbackend.hh \
	backends/gsql/ssql.hh \
	base32.cc \
	base64.cc base64.hh \
	bindlexer.l \
	bindparser.yy \
	cachecleaner.hh \
	dbdnsseckeeper.cc \
	dnsbackend.cc \
	dns.cc \
	dnslabeltext.cc \
	dnspacket.cc \
	dnsparser.cc dnsparser.hh \
	dns_random.cc \
	dnsrecords.cc \
	dnssecinfra.cc dnssecinfra.hh \
	dnssecsigner.cc \
	dnswriter.cc dnswriter.hh \
	dynlistener.cc \
	ednssubnet.cc \
	json.cc \
	logger.cc \
	misc.cc misc.hh \
	nsecrecords.cc \
	packetcache.cc \
	pdnssec.cc \
	polarrsakeyinfra.cc \
	qtype.cc \
	randomhelper.cc \
	rcpgenerator.cc rcpgenerator.hh \
	serialtweaker.cc \
	signingpipe.cc \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	ueberbackend.cc \
	unix_utility.cc \
	zoneparser-tng.cc

pdnssec_LDFLAGS = \
	$(DYNLINKFLAGS) \
	$(THREADFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS) \
	$(BOOST_SERIALIZATION_LDFLAGS)

pdnssec_LDADD = \
	@moduleobjects@ \
	@modulelibs@ \
	$(LIBDL) \
	$(POLARSSL_LIBS) \
	$(BOOST_PROGRAM_OPTIONS_LIBS) \
	$(BOOST_SERIALIZATION_LIBS) \
	$(YAHTTP_LIBS)

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
pdnssec_LDADD += $(SQLITE3_LIBS)
endif

if ORACLE
pdnssec_LDADD += $(ORACLE_LIBS)
endif

if PKCS11
pdnssec_SOURCES +=  pkcs11signers.cc pkcs11signers.hh
pdnssec_LDADD += $(P11KIT1_LIBS)
endif

zone2sql_SOURCES = \
	arguments.cc \
	base32.cc \
	base64.cc \
	bind-dnssec.schema.sqlite3.sql.h \
	bindlexer.l \
	bindparser.yy \
	bindparserclasses.hh \
	dns.cc \
	dns_random.cc \
	dnslabeltext.cc \
	dnsparser.cc \
	dnsrecords.cc \
	dnswriter.cc \
	json.cc json.hh \
	logger.cc \
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc \
	sillyrecords.cc \
	statbag.cc \
	unix_utility.cc \
	zone2sql.cc \
	zoneparser-tng.cc

zone2sql_LDFLAGS = $(THREADFLAGS)
zone2sql_LDADD = $(POLARSSL_LIBS)

zone2json_SOURCES = \
	arguments.cc \
	base32.cc \
	base64.cc \
	bind-dnssec.schema.sqlite3.sql.h \
	bindlexer.l \
	bindparser.yy \
	bindparserclasses.hh \
	dnslabeltext.cc \
	dnsparser.cc \
	dnsrecords.cc \
	dnswriter.cc \
	logger.cc \
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc \
	sillyrecords.cc \
	statbag.cc \
	unix_utility.cc \
	zone2json.cc \
	zoneparser-tng.cc

zone2json_LDFLAGS = $(THREADFLAGS)
zone2json_LDADD = $(POLARSSL_LIBS)

zone2ldap_SOURCES = \
	arguments.cc \
	base32.cc \
	base64.cc \
	bind-dnssec.schema.sqlite3.sql.h \
	bindlexer.l \
	bindparser.yy \
	bindparserclasses.hh \
	dns_random.cc \
	dnslabeltext.cc \
	dnsparser.cc \
	dnsrecords.cc \
	dnswriter.cc \
	logger.cc \
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc \
	sillyrecords.cc \
	statbag.cc \
	unix_utility.cc \
	zone2ldap.cc \
	zoneparser-tng.cc

zone2ldap_LDFLAGS = $(THREADFLAGS)
zone2ldap_LDADD = $(POLARSSL_LIBS)

if LMDB
bin_PROGRAMS += zone2lmdb

zone2lmdb_SOURCES = \
	arguments.cc \
	base32.cc \
	base64.cc \
	bind-dnssec.schema.sqlite3.sql.h \
	bindlexer.l \
	bindparser.yy \
	bindparserclasses.hh \
	dns.cc \
	dns_random.cc \
	dnslabeltext.cc \
	dnsparser.cc \
	dnsrecords.cc \
	dnswriter.cc \
	logger.cc \
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc \
	sillyrecords.cc \
	statbag.cc \
	unix_utility.cc \
	zone2lmdb.cc \
	zoneparser-tng.cc

zone2lmdb_LDFLAGS = $(THREADFLAGS)
zone2lmdb_LDADD = \
	$(POLARSSL_LIBS) \
	$(LMDB_LIBS)
endif

sdig_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dnslabeltext.cc \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	misc.cc misc.hh \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sdig.cc \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	unix_utility.cc

saxfr_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dnslabeltext.cc \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnssecinfra.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	misc.cc misc.hh \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	saxfr.cc \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	unix_utility.cc

saxfr_LDADD= $(POLARSSL_LIBS)

if PKCS11
saxfr_SOURCES +=  pkcs11signers.cc pkcs11signers.hh
saxfr_LDADD += $(P11KIT1_LIBS)
endif

dnstcpbench_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dnslabeltext.cc \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnstcpbench.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	misc.cc misc.hh \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	unix_utility.cc

dnstcpbench_LDFLAGS = $(THREADFLAGS) $(BOOST_PROGRAM_OPTIONS_LDFLAGS)
dnstcpbench_LDADD = $(BOOST_PROGRAM_OPTIONS_LIBS)

dnsdist_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dnsdist.cc \
	dnslabeltext.cc \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnswriter.cc dnswriter.hh \
	iputils.cc \
	logger.cc \
	misc.cc misc.hh \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	unix_utility.cc

dnsdist_LDFLAGS = $(THREADFLAGS) $(BOOST_PROGRAM_OPTIONS_LDFLAGS)
dnsdist_LDADD = $(BOOST_PROGRAM_OPTIONS_LIBS)

nsec3dig_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dnslabeltext.cc \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnssecinfra.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	misc.cc misc.hh \
	nsec3dig.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	unix_utility.cc

nsec3dig_LDADD = $(POLARSSL_LIBS)

if PKCS11
nsec3dig_SOURCES +=  pkcs11signers.cc pkcs11signers.hh
nsec3dig_LDADD += $(P11KIT1_LIBS)
endif

toysdig_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dns_random.cc \
	dnslabeltext.cc \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnswriter.cc dnswriter.hh \
	ednssubnet.cc ednssubnet.hh \
	logger.cc \
	misc.cc misc.hh \
	nsecrecords.cc \
	qtype.cc \
	randomhelper.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	toysdig.cc \
	unix_utility.cc

toysdig_LDADD = $(POLARSSL_LIBS)

tsig_tests_SOURCES = \
	arguments.cc \
	base32.cc \
	base64.cc base64.hh \
	dns.cc \
	dns_random.cc dns_random.hh \
	dnslabeltext.cc \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnssecinfra.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	misc.cc misc.hh \
	nsecrecords.cc \
	qtype.cc \
	randomhelper.cc \
	rcpgenerator.cc rcpgenerator.hh \
	resolver.cc \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	tsig-tests.cc \
	unix_utility.cc

tsig_tests_LDADD = $(POLARSSL_LIBS)

if PKCS11
tsig_tests_SOURCES +=  pkcs11signers.cc pkcs11signers.hh
tsig_tests_LDADD += $(P11KIT1_LIBS)
endif

speedtest_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dnslabeltext.cc \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	misc.cc misc.hh \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	speedtest.cc \
	statbag.cc \
	unix_utility.cc

dnswasher_SOURCES = \
	dnsparser.hh \
	dnspcap.cc dnspcap.hh \
	dnswasher.cc \
	logger.cc \
	misc.cc \
	qtype.cc \
	statbag.cc \
	unix_utility.cc

dnswasher_LDFLAGS = $(THREADFLAGS)

dnsbulktest_SOURCES = \
	base32.cc \
	base64.cc \
	dnsbulktest.cc \
	dnslabeltext.cc \
	dnsparser.cc \
	dnsrecords.cc \
	dnswriter.cc \
	logger.cc \
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc \
	sillyrecords.cc \
	statbag.cc \
	unix_utility.cc

dnsbulktest_LDFLAGS = \
	$(THREADFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS)

dnsbulktest_LDADD = $(BOOST_PROGRAM_OPTIONS_LIBS)

dnsscan_SOURCES = \
	anadns.hh \
	base32.cc \
	base64.cc base64.hh \
	dnslabeltext.cc \
	dnsparser.cc dnsparser.hh \
	dnspcap.cc dnspcap.hh \
	dnsrecords.cc \
	dnsscan.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	statbag.cc \
	unix_utility.cc \
	utility.hh

dnsreplay_SOURCES = \
	anadns.hh \
	base32.cc \
	base64.cc base64.hh \
	dnslabeltext.cc \
	dnsparser.cc dnsparser.hh \
	dnspcap.cc dnspcap.hh \
	dnsrecords.cc \
	dnsreplay.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	statbag.cc \
	unix_utility.cc \
	utility.hh

dnsreplay_LDFLAGS = \
	$(THREADFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS)

dnsreplay_LDADD = $(BOOST_PROGRAM_OPTIONS_LIBS)

nproxy_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dnslabeltext.cc \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	misc.cc \
	mplexer.hh \
	nproxy.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	selectmplexer.cc \
	sillyrecords.cc \
	statbag.cc \
	unix_utility.cc

nproxy_LDFLAGS = \
	$(THREADFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS)

nproxy_LDADD = $(BOOST_PROGRAM_OPTIONS_LIBS)

notify_SOURCES = \
	arguments.cc \
	base32.cc \
	base64.cc base64.hh \
	dns.cc \
	dnslabeltext.cc \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	misc.cc \
	notify.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	selectmplexer.cc \
	sillyrecords.cc \
	statbag.cc \
	unix_utility.cc

notify_LDFLAGS = \
	$(THREADFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS)

notify_LDADD = $(BOOST_PROGRAM_OPTIONS_LIBS)

dnsscope_SOURCES = \
	arguments.cc \
	base32.cc \
	base64.cc base64.hh \
	dns.cc \
	dnslabeltext.cc \
	dnsparser.cc dnsparser.hh \
	dnspcap.cc dnspcap.hh \
	dnsrecords.cc \
	dnsscope.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	statbag.cc \
	unix_utility.cc \
	utility.hh

dnsscope_LDFLAGS = \
	$(THREADFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS)

dnsscope_LDADD = $(BOOST_PROGRAM_OPTIONS_LIBS)

dnsgram_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dnsgram.cc \
	dnslabeltext.cc \
	dnsparser.cc dnsparser.hh \
	dnspcap.cc dnspcap.hh \
	dnsrecords.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	statbag.cc \
	unix_utility.cc \
	utility.hh

dnsdemog_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dnsdemog.cc \
	dnslabeltext.cc \
	dnsparser.cc dnsparser.hh \
	dnspcap.cc dnspcap.hh \
	dnsrecords.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	statbag.cc \
	unix_utility.cc \
	utility.hh

rec_control_SOURCES = \
	arguments.cc arguments.hh \
	logger.cc \
	misc.cc \
	qtype.cc \
	rec_channel.cc rec_channel.hh \
	rec_control.cc \
	statbag.cc \
	unix_utility.cc

testrunner_SOURCES = \
	arguments.cc \
	base32.cc \
	base64.cc \
	bindlexer.l \
	bindparser.yy \
	dns.cc \
	dns_random.cc \
	dnslabeltext.cc \
	dnspacket.cc \
	dnsparser.cc \
	dnsrecords.cc \
	dnssecinfra.cc \
	dnswriter.cc \
	ednssubnet.cc \
	logger.cc \
	misc.cc \
	nameserver.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc \
	responsestats.cc \
	sillyrecords.cc \
	statbag.cc \
	test-base32_cc.cc \
	test-base64_cc.cc \
	test-bindparser_cc.cc \
	test-dns_random_hh.cc \
	test-dnsrecords_cc.cc \
	test-iputils_hh.cc \
	test-md5_hh.cc \
	test-misc_hh.cc \
	test-nameserver_cc.cc \
	test-packetcache_cc.cc \
	test-rcpgenerator_cc.cc \
	test-statbag_cc.cc \
	test-zoneparser_tng_cc.cc \
	testrunner.cc \
        test-sha_hh.cc \
        packetcache.cc \
	unix_utility.cc \
        zoneparser-tng.cc zoneparser-tng.hh

testrunner_LDFLAGS = \
	$(THREADFLAGS) \
	$(BOOST_UNIT_TEST_FRAMEWORK_LDFLAGS)

testrunner_LDADD = \
	$(POLARSSL_LIBS) \
	$(BOOST_UNIT_TEST_FRAMEWORK_LIBS)

if PKCS11
testrunner_SOURCES += pkcs11signers.cc pkcs11signers.hh
testrunner_LDADD += $(P11KIT1_LIBS)
endif

pdns_recursor_SOURCES = \
	arguments.cc \
	base32.cc \
	base64.cc base64.hh \
	cachecleaner.hh \
	dns.cc \
	dns_random.cc \
	dnslabeltext.cc \
	dnsparser.cc \
	dnsrecords.cc dnsrecords.hh \
	dnswriter.cc dnswriter.hh \
	epollmplexer.cc \
	htimer.cc htimer.hh \
	json.cc json.hh \
	logger.cc \
	lua-pdns.cc lua-pdns.hh \
	lua-recursor.cc lua-recursor.hh \
	lwres.cc lwres.hh \
	misc.cc \
	mtasker.hh \
	nsecrecords.cc \
	pdns_recursor.cc \
	qtype.cc \
	randomhelper.cc \
	rcpgenerator.cc rcpgenerator.hh \
	rec-carbon.cc \
	rec_channel.cc rec_channel.hh \
	rec_channel_rec.cc \
	recpacketcache.cc recpacketcache.hh \
	recursor_cache.cc recursor_cache.hh \
	reczones.cc \
	resolver.hh \
	responsestats.cc \
	secpoll-recursor.cc \
	secpoll-recursor.hh \
	selectmplexer.cc \
	sillyrecords.cc \
	statbag.cc \
	syncres.cc syncres.hh \
	unix_utility.cc \
	version.cc version.hh \
	webserver.cc webserver.hh \
	ws-api.cc ws-api.hh \
	ws-recursor.cc ws-recursor.hh \
	zoneparser-tng.cc zoneparser-tng.hh

pdns_recursor_LDFLAGS = $(THREADFLAGS)
pdns_recursor_LDADD = \
	$(POLARSSL_LIBS) \
	$(YAHTTP_LIBS)

if LUA
pdns_recursor_LDADD += $(LUA_LIBS)
endif

pdns_control_SOURCES = \
	arguments.cc \
	dynloader.cc \
	dynmessenger.cc \
	logger.cc \
	misc.cc \
	qtype.cc \
	statbag.cc \
	unix_utility.cc

pdns_control_LDFLAGS = $(THREADFLAGS)

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

build_date = $(shell LC_TIME=C date '+%Y%m%d%H%M%S')
build_host = $(shell id -u -n)@$(shell hostname -f)
if RELEASE_BUILD
pdns_version = $(PACKAGE_VERSION)
dist_host = $(DIST_HOST)
else
git_version = $(shell git describe --always --dirty=+ 2>/dev/null)
# Do the test in shell, so we don't confuse automake with ifeq/ifneq.
pdns_version = $(shell test -z "$(git_version)" && echo UNKNOWN || echo "git-$(git_version)")
dist_host = $(build_host)
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
