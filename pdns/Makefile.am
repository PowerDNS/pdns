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
	pdnsutil \
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
	ixplore \
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
	kvresp \
	ixplore \
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
	zone2ldap

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
	lua-pdns.cc lua-pdns.hh lua-iputils.cc \
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
	$(DYNLINKFLAGS) 

pdns_server_LDADD = \
	@moduleobjects@ \
	@modulelibs@ \
	$(LIBDL) \
	$(MBEDTLS_LIBS) \
	$(YAHTTP_LIBS)

if BOTAN110
pdns_server_SOURCES += botan110signers.cc botansigners.cc
pdns_server_LDADD += $(BOTAN110_LIBS)
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

pdnsutil_SOURCES = \
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
        iputils.cc iputils.hh \
	json.cc \
	logger.cc \
	mbedtlscompat.hh \
	misc.cc misc.hh \
	nsecrecords.cc \
	packetcache.cc \
	pdnsutil.cc \
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

pdnsutil_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(DYNLINKFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS) 

pdnsutil_LDADD = \
	@moduleobjects@ \
	@modulelibs@ \
	$(LIBDL) \
	$(MBEDTLS_LIBS) \
	$(BOOST_PROGRAM_OPTIONS_LIBS) \
	$(YAHTTP_LIBS)

if BOTAN110
pdnsutil_SOURCES += botan110signers.cc botansigners.cc
pdnsutil_LDADD += $(BOTAN110_LIBS)
endif

if CRYPTOPP
pdnsutil_SOURCES += cryptoppsigners.cc
pdnsutil_LDADD += $(CRYPTOPP_LIBS)
endif

if LIBSODIUM
pdnsutil_SOURCES += sodiumsigners.cc
pdnsutil_LDADD += $(LIBSODIUM_LIBS)
endif

if SQLITE3
pdnsutil_SOURCES += ssqlite3.cc ssqlite3.hh
pdnsutil_LDADD += $(SQLITE3_LIBS)
endif

if ORACLE
pdnsutil_LDADD += $(ORACLE_LIBS)
endif

if PKCS11
pdnsutil_SOURCES +=  pkcs11signers.cc pkcs11signers.hh
pdnsutil_LDADD += $(P11KIT1_LIBS)
endif

if GSS_TSIG
pdnsutil_LDADD += $(GSS_LIBS)
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

sdig_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dns.cc \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnswriter.cc dnswriter.hh \
	ednssubnet.cc \
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

kvresp_SOURCES = \
	dnslabeltext.cc dnsname.cc dnsname.hh \
	kvresp.cc \
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


ixplore_SOURCES = \
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
	rcpgenerator.cc rcpgenerator.hh \
	resolver.cc \
	ixfr.cc ixfr.hh \
	ixplore.cc \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	unix_utility.cc zoneparser-tng.cc

ixplore_LDADD = $(MBEDTLS_LIBS)

if PKCS11
ixplore_SOURCES += pkcs11signers.cc pkcs11signers.hh
ixplore_LDADD += $(P11KIT1_LIBS)
endif

if GSS_TSIG
ixplore_LDADD += $(GSS_LIBS)
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
	dns.cc \
	dnscrypt.cc dnscrypt.hh \
	dnsparser.hh dnsparser.cc \
	ednssubnet.cc ednssubnet.hh \
	dnsdist.cc \
	dnsdist-carbon.cc \
	dnsdist-console.cc \
	dnsdist-dnscrypt.cc \
	dnsdist-ecs.cc dnsdist-ecs.hh \
	dnsdist-lua.cc \
	dnsdist-lua2.cc \
	dnsdist-rings.cc \
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
	dnssecinfra.cc \
	dnswriter.cc dnswriter.hh \
	ednssubnet.cc ednssubnet.hh \
	gss_context.cc gss_context.hh \
	logger.cc \
	mbedtlscompat.hh \
	mbedtlssigners.cc \
	misc.cc misc.hh \
	nsecrecords.cc \
	qtype.cc \
	randomhelper.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	toysdig.cc \
	unix_utility.cc \
	validate.cc validate.hh


toysdig_LDADD = $(MBEDTLS_LIBS)
if GSS_TSIG
toysdig_LDADD += $(GSS_LIBS)
endif

if BOTAN110
toysdig_SOURCES += botan110signers.cc botansigners.cc
toysdig_LDADD += $(BOTAN110_LIBS)
endif

if PKCS11
toysdig_SOURCES += pkcs11signers.cc pkcs11signers.hh
toysdig_LDADD += $(P11KIT1_LIBS)
endif


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
	test-nmtree.cc \
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
	$(BOOST_UNIT_TEST_FRAMEWORK_LDFLAGS) 

testrunner_LDADD = \
	$(MBEDTLS_LIBS) \
	$(BOOST_UNIT_TEST_FRAMEWORK_LIBS) \
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
	dnssecinfra.cc \
	dnswriter.cc dnswriter.hh \
	ednssubnet.cc ednssubnet.hh \
	filterpo.cc filterpo.hh \
	gss_context.cc gss_context.hh \
	iputils.cc \
	ixfr.cc ixfr.hh \
	json.cc json.hh \
	logger.cc \
	lua-recursor4.cc lua-recursor4.hh \
	lwres.cc lwres.hh \
	mbedtlscompat.hh \
	mbedtlssigners.cc \
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
	rec-lua-conf.cc \
	recpacketcache.cc recpacketcache.hh \
	recursor_cache.cc recursor_cache.hh \
	reczones.cc \
	resolver.cc \
	resolver.hh \
	responsestats.cc \
	rpzloader.cc rpzloader.hh \
	secpoll-recursor.cc \
	secpoll-recursor.hh \
	selectmplexer.cc \
	sillyrecords.cc \
	sortlist.cc sortlist.hh \
	statbag.cc \
	syncres.cc syncres.hh \
	unix_utility.cc \
	validate.cc validate.hh validate-recursor.cc validate-recursor.hh \
	version.cc version.hh \
	webserver.cc webserver.hh \
	ws-api.cc ws-api.hh \
	ws-recursor.cc ws-recursor.hh \
	zoneparser-tng.cc zoneparser-tng.hh

pdns_recursor_LDADD = \
	$(MBEDTLS_LIBS) \
	$(YAHTTP_LIBS)

if PKCS11
pdns_recursor_SOURCES += pkcs11signers.cc pkcs11signers.hh
pdns_recursor_LDADD += $(P11KIT1_LIBS)
endif

if BOTAN110
pdns_recursor_SOURCES += botan110signers.cc botansigners.cc
pdns_recursor_LDADD += $(BOTAN110_LIBS)
endif


pdns_recursor_LDFLAGS = $(AM_LDFLAGS)

if MALLOC_TRACE
pdns_recursor_SOURCES += malloctrace.cc malloctrace.hh 
pdns_recursor_LDFLAGS += -rdynamic
endif

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

curl_verbose = $(curl_verbose_$(V))
curl_verbose_ = $(curl_verbose_$(AM_DEFAULT_VERBOSITY))
curl_verbose_0 = @echo "  CURL    " $@;
$(srcdir)/effective_tld_names.dat:
	$(curl_verbose)if ! curl -s https://publicsuffix.org/list/public_suffix_list.dat > $@; then rm -f $@; exit 1; fi

pubsuffix.cc: $(srcdir)/effective_tld_names.dat
	$(AM_V_GEN)./mkpubsuffixcc
