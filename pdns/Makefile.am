AM_CPPFLAGS += \
	-I$(top_srcdir)/ext/json11 \
	-I$(top_srcdir)/ext/rapidjson/include \
	$(YAHTTP_CFLAGS) \
	$(MBEDTLS_CFLAGS)

AM_CXXFLAGS = \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DPKGLIBDIR=\"$(pkglibdir)\" \
	-DLOCALSTATEDIR=\"$(socketdir)\"

AM_LDFLAGS = \
	$(PROGRAM_LDFLAGS) \
	$(THREADFLAGS)

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

if GSS_TSIG
AM_CPPFLAGS +=$(GSS_CFLAGS)
endif

EXTRA_DIST = \
	dnslabeltext.rl \
	dnslabeltext.cc \
	effective_tld_names.dat \
	mtasker.cc \
	inflighter.cc \
	bind-dnssec.schema.sqlite3.sql \
	bindparser.h \
	named.conf.parsertest \
	pdns.conf-dist \
	dnsdistdist/html \
	delaypipe.hh delaypipe.cc

BUILT_SOURCES = \
	bind-dnssec.schema.sqlite3.sql.h \
	bindparser.h htmlfiles.h 

CLEANFILES = \
	*.gcda \
	*.gcno \
	*.gcov \
	backends/gsql/gsqlbackend.gcda \
	backends/gsql/gsqlbackend.gcno \
	backends/gsql/gsqlbackend.gcov

noinst_SCRIPTS = pdns.init
sysconf_DATA = pdns.conf-dist

sbin_PROGRAMS = pdns_server
bin_PROGRAMS = \
	pdns_control \
	pdnssec \
	zone2sql \
	zone2json

if TOOLS
bin_PROGRAMS += \
	dnsbulktest \
	dnsgram \
	dnsreplay \
	dnsscan \
	dnsscope \
	dnstcpbench \
	dnswasher \
	dumresp \
	notify \
	nproxy \
	nsec3dig \
	saxfr \
	sdig

if HAVE_RECVMMSG
bin_PROGRAMS += calidns
endif

endif

EXTRA_PROGRAMS = \
	calidns \
	dnsbulktest \
	dnsdemog \
	dnsdist \
	dnsgram \
	dnsreplay \
	dnsscan \
	dnsscope \
	dnstcpbench \
	dnswasher \
	dumresp \
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
	zone2ldap \
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
	dnsname.cc dnsname.hh \
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
	gss_context.cc gss_context.hh \
	iputils.cc iputils.hh \
	json.cc json.hh \
	lock.hh \
	logger.cc logger.hh \
	lua-auth.cc lua-auth.hh \
	lua-pdns.cc lua-iputils.cc \
	mastercommunicator.cc \
	mbedtlscompat.hh \
	md5.hh \
	misc.cc misc.hh \
	nameserver.cc nameserver.hh \
	namespaces.hh \
	nsecrecords.cc \
	packetcache.cc packetcache.hh \
	packethandler.cc packethandler.hh \
	pdnsexception.hh \
	mbedtlssigners.cc \
	qtype.cc qtype.hh \
	randomhelper.cc \
	rcpgenerator.cc \
	receiver.cc \
	resolver.cc resolver.hh \
	responsestats.cc responsestats.hh responsestats-auth.cc \
	rfc2136handler.cc \
	secpoll-auth.cc secpoll-auth.hh \
	serialtweaker.cc \
	sha.hh \
	signingpipe.cc signingpipe.hh \
	sillyrecords.cc \
	slavecommunicator.cc \
	statbag.cc statbag.hh \
	tcpreceiver.cc tcpreceiver.hh \
	tkey.cc \
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
	$(AM_LDFLAGS) \
	$(DYNLINKFLAGS) \
	$(BOOST_SERIALIZATION_LDFLAGS)

pdns_server_LDADD = \
	@moduleobjects@ \
	@modulelibs@ \
	$(LIBDL) \
	$(MBEDTLS_LIBS) \
	$(BOOST_SERIALIZATION_LIBS) \
	$(YAHTTP_LIBS)

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

if LIBSODIUM
pdns_server_SOURCES += sodiumsigners.cc
pdns_server_LDADD += $(LIBSODIUM_LIBS)
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

if GSS_TSIG
pdns_server_LDADD += $(GSS_LIBS)
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
	dnsname.cc dnsname.hh \
	dnspacket.cc \
	dnsparser.cc dnsparser.hh \
	dns_random.cc \
	dnsrecords.cc \
	dnssecinfra.cc dnssecinfra.hh \
	dnssecsigner.cc \
	dnswriter.cc dnswriter.hh \
	dynlistener.cc \
	ednssubnet.cc \
	gss_context.cc gss_context.hh \
	json.cc \
	logger.cc \
	mbedtlscompat.hh \
	misc.cc misc.hh \
	nsecrecords.cc \
	packetcache.cc \
	pdnssec.cc \
	mbedtlssigners.cc \
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
	$(AM_LDFLAGS) \
	$(DYNLINKFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS) \
	$(BOOST_SERIALIZATION_LDFLAGS)

pdnssec_LDADD = \
	@moduleobjects@ \
	@modulelibs@ \
	$(LIBDL) \
	$(MBEDTLS_LIBS) \
	$(BOOST_PROGRAM_OPTIONS_LIBS) \
	$(BOOST_SERIALIZATION_LIBS) \
	$(YAHTTP_LIBS)

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
pdnssec_LDADD += $(CRYPTOPP_LIBS)
endif

if LIBSODIUM
pdnssec_SOURCES += sodiumsigners.cc
pdnssec_LDADD += $(LIBSODIUM_LIBS)
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

if GSS_TSIG
pdnssec_LDADD += $(GSS_LIBS)
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
	dnsname.cc dnsname.hh \
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

zone2sql_LDADD = $(MBEDTLS_LIBS)

zone2json_SOURCES = \
	arguments.cc \
	base32.cc \
	base64.cc \
	bind-dnssec.schema.sqlite3.sql.h \
	bindlexer.l \
	bindparser.yy \
	bindparserclasses.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
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

zone2json_LDADD = $(MBEDTLS_LIBS) -L$(top_srcdir)/ext/json11 -ljson11

# pkglib_LTLIBRARIES = iputils.la
# iputils_la_SOURCES = lua-iputils.cc
# iputils_la_LDFLAGS= -module -avoid-version

if LDAP
bin_PROGRAMS += zone2ldap
endif

zone2ldap_SOURCES = \
	arguments.cc \
	base32.cc \
	base64.cc \
	bind-dnssec.schema.sqlite3.sql.h \
	bindlexer.l \
	bindparser.yy \
	bindparserclasses.hh \
	dns_random.cc \
	dnsname.cc dnsname.hh \
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

zone2ldap_LDADD = $(MBEDTLS_LIBS)

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
	dnsname.cc dnsname.hh \
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

zone2lmdb_LDADD = \
	$(MBEDTLS_LIBS) \
	$(LMDB_LIBS)
endif

sdig_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	mbedtlscompat.hh \
	misc.cc misc.hh \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sdig.cc \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	unix_utility.cc

sdig_LDADD = $(MBEDTLS_LIBS)

calidns_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	calidns.cc \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnswriter.cc dnswriter.hh \
	iputils.cc \
	logger.cc \
	mbedtlscompat.hh \
	misc.cc misc.hh \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	unix_utility.cc

calidns_LDADD = $(MBEDTLS_LIBS)
calidns_LDFLAGS=$(THREADFLAGS) 

dumresp_SOURCES = \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dumresp.cc \
	logger.cc \
	misc.cc misc.hh \
	statbag.cc \
	unix_utility.cc \
	qtype.cc 


saxfr_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
        dns_random.cc dns_random.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnssecinfra.cc \
	dnswriter.cc dnswriter.hh \
	gss_context.cc gss_context.hh \
	logger.cc \
	mbedtlscompat.hh \
	misc.cc misc.hh \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	saxfr.cc \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	unix_utility.cc

saxfr_LDADD = $(MBEDTLS_LIBS)

if PKCS11
saxfr_SOURCES += pkcs11signers.cc pkcs11signers.hh
saxfr_LDADD += $(P11KIT1_LIBS)
endif

if GSS_TSIG
saxfr_LDADD += $(GSS_LIBS)
endif

dnstcpbench_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnstcpbench.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	mbedtlscompat.hh \
	misc.cc misc.hh \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	unix_utility.cc

dnstcpbench_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS)

dnstcpbench_LDADD = \
	$(MBEDTLS_LIBS) \
	$(BOOST_PROGRAM_OPTIONS_LIBS)

dnsdist_SOURCES = \
	base32.cc \
	base64.hh \
	dnsdist.cc \
	dnsdist-carbon.cc \
	dnsdist-lua.cc \
	dnsdist-tcp.cc \
	dnsdist-web.cc \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnswriter.cc \
	dolog.hh \
	iputils.cc \
	htmlfiles.h \
	mbedtlscompat.hh \
	misc.cc misc.hh \
	qtype.cc \
	sholder.hh \
	sodcrypto.cc sodcrypto.hh \
	sstuff.hh \
	../ext/json11/json11.cpp

dnsdist_LDFLAGS = \
	$(AM_LDFLAGS) 

dnsdist_LDADD = \
	$(LUA_LIBS) \
	$(READLINE_LIBS) \
	$(RT_LIBS) \
	$(YAHTTP_LIBS) \
	$(LIBSODIUM_LIBS)

nsec3dig_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dnsname.cc dnsname.hh \
	dnslabeltext.cc \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnssecinfra.cc \
	dnswriter.cc dnswriter.hh \
	gss_context.cc gss_context.hh \
	logger.cc \
	mbedtlscompat.hh \
	misc.cc misc.hh \
	nsec3dig.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	unix_utility.cc

nsec3dig_LDADD = $(MBEDTLS_LIBS)

if PKCS11
nsec3dig_SOURCES += pkcs11signers.cc pkcs11signers.hh
nsec3dig_LDADD += $(P11KIT1_LIBS)
endif

if GSS_TSIG
nsec3dig_LDADD += $(GSS_LIBS)
endif

toysdig_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dns_random.cc \
	dnsname.cc dnsname.hh \
	dnslabeltext.cc \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnswriter.cc dnswriter.hh \
	ednssubnet.cc ednssubnet.hh \
	logger.cc \
	mbedtlscompat.hh \
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

toysdig_LDADD = $(MBEDTLS_LIBS)

tsig_tests_SOURCES = \
	arguments.cc \
	base32.cc \
	base64.cc base64.hh \
	dns.cc \
	dns_random.cc dns_random.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnssecinfra.cc \
	dnswriter.cc dnswriter.hh \
	gss_context.cc gss_context.hh \
	logger.cc \
	mbedtlscompat.hh \
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

tsig_tests_LDADD = $(MBEDTLS_LIBS)

if PKCS11
tsig_tests_SOURCES += pkcs11signers.cc pkcs11signers.hh
tsig_tests_LDADD += $(P11KIT1_LIBS)
endif

if GSS_TSIG
tsig_tests_LDADD += $(GSS_LIBS)
endif
speedtest_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	mbedtlscompat.hh \
	misc.cc misc.hh \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	speedtest.cc \
	statbag.cc \
	unix_utility.cc

speedtest_LDADD = $(MBEDTLS_LIBS) \
	$(RT_LIBS)

dnswasher_SOURCES = \
	dnslabeltext.cc \
	dnsname.hh dnsname.cc \
	dnsparser.hh \
	dnspcap.cc dnspcap.hh \
	dnswasher.cc \
	dnswriter.hh \
	logger.cc \
	misc.cc \
	qtype.cc \
	statbag.cc \
	unix_utility.cc


dnsbulktest_SOURCES = \
	base32.cc \
	base64.cc \
	dnsbulktest.cc \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
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
	$(AM_LDFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS)

dnsbulktest_LDADD = \
	$(MBEDTLS_LIBS) \
	$(BOOST_PROGRAM_OPTIONS_LIBS)

dnsscan_SOURCES = \
	anadns.hh \
	base32.cc \
	base64.cc base64.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnspcap.cc dnspcap.hh \
	dnsrecords.cc \
	dnsscan.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	mbedtlscompat.hh \
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	statbag.cc \
	unix_utility.cc \
	utility.hh

dnsscan_LDADD = $(MBEDTLS_LIBS)

dnsreplay_SOURCES = \
	anadns.hh \
	base32.cc \
	base64.cc base64.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnspcap.cc dnspcap.hh \
	dnsrecords.cc \
	dnsreplay.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	mbedtlscompat.hh \
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	statbag.cc \
	unix_utility.cc \
	utility.hh

dnsreplay_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS)

dnsreplay_LDADD = \
	$(MBEDTLS_LIBS) \
	$(BOOST_PROGRAM_OPTIONS_LIBS)

nproxy_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	mbedtlscompat.hh \
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
	$(AM_LDFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS)

nproxy_LDADD = \
	$(MBEDTLS_LIBS) \
	$(BOOST_PROGRAM_OPTIONS_LIBS)

notify_SOURCES = \
	arguments.cc \
	base32.cc \
	base64.cc base64.hh \
	dns.cc \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	mbedtlscompat.hh \
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
	$(AM_LDFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS)

notify_LDADD = \
	$(MBEDTLS_LIBS) \
	$(BOOST_PROGRAM_OPTIONS_LIBS)

dnsscope_SOURCES = \
	arguments.cc \
	base32.cc \
	base64.cc base64.hh \
	dns.cc \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnspcap.cc dnspcap.hh \
	dnsrecords.cc \
	dnsscope.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	mbedtlscompat.hh \
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	statbag.cc \
	unix_utility.cc \
	utility.hh

dnsscope_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS)

dnsscope_LDADD = \
	$(MBEDTLS_LIBS) \
	$(BOOST_PROGRAM_OPTIONS_LIBS)

dnsgram_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dnsgram.cc \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnspcap.cc dnspcap.hh \
	dnsrecords.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	mbedtlscompat.hh \
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	statbag.cc \
	unix_utility.cc \
	utility.hh

dnsgram_LDADD = $(MBEDTLS_LIBS)

dnsdemog_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dnsdemog.cc \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnspcap.cc dnspcap.hh \
	dnsrecords.cc \
	dnswriter.cc dnswriter.hh \
	logger.cc \
	mbedtlscompat.hh \
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	statbag.cc \
	unix_utility.cc \
	utility.hh

dnsdemog_LDADD = $(MBEDTLS_LIBS)

rec_control_SOURCES = \
	arguments.cc arguments.hh \
	dnsname.hh dnsname.cc \
	dnslabeltext.cc \
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
	dnsbackend.cc \
	dnslabeltext.cc \
	dnsname.cc \
	dnsname.hh \
	dnspacket.cc \
	dnsparser.cc \
	dnsrecords.cc \
	dnssecinfra.cc \
	dnswriter.cc \
	ednssubnet.cc \
        gss_context.cc gss_context.hh \
	iputils.cc \
	logger.cc \
	misc.cc \
	nameserver.cc \
	nsecrecords.cc \
	packetcache.cc \
	qtype.cc \
	rcpgenerator.cc \
	responsestats.cc \
	responsestats-auth.cc \
	sillyrecords.cc \
	statbag.cc \
	test-arguments_cc.cc \
	test-base32_cc.cc \
	test-base64_cc.cc \
	test-bindparser_cc.cc \
	test-delaypipe_hh.cc \
	test-distributor_hh.cc \
	test-dns_random_hh.cc \
	test-dnsname_cc.cc \
	test-dnsrecords_cc.cc \
	test-iputils_hh.cc \
	test-md5_hh.cc \
	test-misc_hh.cc \
	test-nameserver_cc.cc \
	test-packetcache_cc.cc \
	test-rcpgenerator_cc.cc \
	test-sha_hh.cc \
	test-sholder_hh.cc \
	test-statbag_cc.cc \
	test-zoneparser_tng_cc.cc \
	testrunner.cc \
	ueberbackend.cc \
	unix_utility.cc \
	zoneparser-tng.cc zoneparser-tng.hh

testrunner_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(BOOST_UNIT_TEST_FRAMEWORK_LDFLAGS) \
	$(BOOST_SERIALIZATION_LDFLAGS)

testrunner_LDADD = \
	$(MBEDTLS_LIBS) \
	$(BOOST_UNIT_TEST_FRAMEWORK_LIBS) \
	$(BOOST_SERIALIZATION_LIBS) \
	$(RT_LIBS) \
	$(LIBDL)

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
	dnsname.cc dnsname.hh \
	dnsparser.cc \
	dnsrecords.cc dnsrecords.hh \
	dnswriter.cc dnswriter.hh \
	iputils.cc \
	json.cc json.hh \
	logger.cc \
	lua-pdns.cc lua-pdns.hh lua-iputils.cc \
	lua-recursor.cc lua-recursor.hh \
	lwres.cc lwres.hh \
	mbedtlscompat.hh \
	misc.cc \
	mtasker.hh \
	nsecrecords.cc \
	pdns_recursor.cc \
	pubsuffix.cc \
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

pdns_recursor_LDADD = \
	$(MBEDTLS_LIBS) \
	$(YAHTTP_LIBS)

if LUA
pdns_recursor_LDADD += $(LUA_LIBS)
endif

if HAVE_FREEBSD
pdns_recursor_SOURCES += kqueuemplexer.cc
endif

if HAVE_LINUX
pdns_recursor_SOURCES += epollmplexer.cc
endif

if HAVE_SOLARIS
pdns_recursor_SOURCES += \
	devpollmplexer.cc \
	portsmplexer.cc
endif

pdns_control_SOURCES = \
	arguments.cc \
	dynloader.cc \
	dynmessenger.cc \
	logger.cc \
	misc.cc \
	qtype.cc \
	statbag.cc \
	unix_utility.cc \
	dnsname.cc \
	dnslabeltext.cc


if UNIT_TESTS
TESTS_ENVIRONMENT = env BOOST_TEST_LOG_LEVEL=message SRCDIR='$(srcdir)'
TESTS=testrunner
else
check-local:
	@echo "Unit tests are not enabled"
	@echo "Run ./configure --enable-unit-tests"
endif

dnslabeltext.cc: dnslabeltext.rl
	$(AM_V_GEN)$(RAGEL) $< -o dnslabeltext.cc

htmlfiles.h: $(srcdir)/dnsdistdist/html/*
	$(srcdir)/dnsdistdist/incfiles $(srcdir)/dnsdistdist > $@

bind-dnssec.schema.sqlite3.sql.h: bind-dnssec.schema.sqlite3.sql
	( echo 'static char sqlCreate[] __attribute__((unused))=' ; sed 's/$$/"/g' $< | sed 's/^/"/g'  ; echo ';' ) > $@

# for bindparser.h/hh
.hh.h:
	cp $< $@

pubsuffix.cc: $(srcdir)/effective_tld_names.dat
	./mkpubsuffixcc
