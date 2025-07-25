JSON11_LIBS = $(top_builddir)/ext/json11/libjson11.la
ARC4RANDOM_LIBS = $(top_builddir)/ext/arc4random/libarc4random.la

AM_CPPFLAGS += \
	-I$(top_srcdir)/ext/json11 \
	$(YAHTTP_CFLAGS) \
	$(LIBEDIT_CFLAGS) \
	$(LIBCRYPTO_INCLUDES) \
	$(SYSTEMD_CFLAGS) \
	$(YAML_CFLAGS) \
	-I$(top_srcdir)/ext/protozero/include \
	-DBOOST_CONTAINER_USE_STD_EXCEPTIONS

AM_CXXFLAGS = \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DPKGLIBDIR=\"$(pkglibdir)\" \
	-DLOCALSTATEDIR=\"$(socketdir)\"

AM_LDFLAGS = \
	$(PROGRAM_LDFLAGS) \
	$(LIBCRYPTO_LIBS) \
	$(ARC4RANDOM_LIBS) \
	$(THREADFLAGS)

AM_LFLAGS = -i
AM_YFLAGS = -d --verbose --debug

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

if LIBSODIUM
AM_CPPFLAGS +=$(LIBSODIUM_CFLAGS)
endif

EXTRA_DIST = \
	api-swagger.json \
	api-swagger.yaml \
	bindparser.hh \
	convert-yaml-to-json.py \
	dnslabeltext.cc \
	dnslabeltext.rl \
	dnsmessage.proto \
	incfiles \
	inflighter.cc \
	ixfrdist.example.yml \
	ixfrdist.service.in \
	lua-record.cc \
	minicurl.cc \
	minicurl.hh \
	named.conf.parsertest \
	pdns.service.in \
	requirements.txt \
	standalone_fuzz_target_runner.cc

BUILT_SOURCES = \
	bind-dnssec.schema.sqlite3.sql.h \
	bindparser.hh \
	dnslabeltext.cc \
	apidocfiles.h

CLEANFILES = \
	*.gcda \
	*.gcno \
	*.gcov \
	backends/gsql/gsqlbackend.gcda \
	backends/gsql/gsqlbackend.gcno \
	backends/gsql/gsqlbackend.gcov \
	pdns.conf-dist \
	apidocfiles.h

if !HAVE_API_SWAGGER_JSON
# don't clean these files if they were present
# at 'configure' time (e.g. from a source dist)
CLEANFILES += \
	api-swagger.yaml \
	api-swagger.json
endif

# use a $(wildcard) wrapper here to allow build to proceed if output
# file is present but input file is not (e.g. in a dist tarball)
api-swagger.yaml: $(wildcard ${srcdir}/../docs/http-api/swagger/authoritative-api-swagger.yaml)
	cp $< $@

if HAVE_VENV
api-swagger.json: api-swagger.yaml requirements.txt
	$(PYTHON) -m venv .venv
	.venv/bin/pip install -U pip setuptools
	.venv/bin/pip install -r ${srcdir}/requirements.txt
	.venv/bin/python ${srcdir}/convert-yaml-to-json.py $< $@
else # if HAVE_VENV
if !HAVE_API_SWAGGER_JSON
api-swagger.json:
	echo "You need Python 3 and the 'venv' module to generate the JSON API document"
	exit 1
endif
endif

apidocfiles.h: api-swagger.yaml api-swagger.json
	$(AM_V_GEN)$(srcdir)/incfiles $^ > $@.tmp
	@mv $@.tmp $@

sysconf_DATA = pdns.conf-dist

sbin_PROGRAMS = pdns_server
bin_PROGRAMS = \
	pdns_control \
	pdnsutil \
	zone2sql \
	zone2json

if TOOLS
bin_PROGRAMS += \
	dnsgram \
	dnspcap2calidns \
	dnspcap2protobuf \
	dnsreplay \
	dnsscan \
	dnsscope \
	dnswasher \
	dumresp \
	pdns_notify \
	nproxy \
	nsec3dig \
	saxfr \
	stubquery \
	ixplore \
	sdig

bin_PROGRAMS += calidns

bin_PROGRAMS += \
	dnsbulktest \
	dnstcpbench

endif # TOOLS

if IXFRDIST
bin_PROGRAMS += \
	ixfrdist

sysconf_DATA += \
	ixfrdist.example.yml
endif

EXTRA_PROGRAMS = \
	calidns \
	comfun \
	dnsbulktest \
	dnsdemog \
	dnsgram \
	dnspcap2calidns \
	dnspcap2protobuf \
	dnsreplay \
	dnsscan \
	dnsscope \
	dnstcpbench \
	dnswasher \
	dumresp \
	kvresp \
	ixplore \
	ixfrdist \
	pdns_notify \
	nproxy \
	nsec3dig \
	saxfr \
	stubquery \
	sdig \
	speedtest \
	testrunner \
	tsig_tests \
	zone2ldap

pdns_server_SOURCES = \
	arguments.cc arguments.hh \
	auth-caches.cc auth-caches.hh \
	auth-carbon.cc \
	auth-catalogzone.cc auth-catalogzone.hh \
	auth-main.cc auth-main.hh \
	auth-packetcache.cc auth-packetcache.hh \
	auth-primarycommunicator.cc \
	auth-querycache.cc auth-querycache.hh \
	auth-secondarycommunicator.cc \
	auth-zonecache.cc auth-zonecache.hh \
	axfr-retriever.cc axfr-retriever.hh \
	backends/gsql/gsqlbackend.cc backends/gsql/gsqlbackend.hh \
	backends/gsql/ssql.hh \
	base32.cc base32.hh \
	base64.cc base64.hh \
	bind-dnssec.schema.sqlite3.sql.h \
	bindlexer.l \
	bindparser.cc \
	burtle.hh \
	cachecleaner.hh \
	check-zone.cc check-zone.hh \
	circular_buffer.hh \
	comment.hh \
	communicator.cc communicator.hh \
	coverage.cc coverage.hh \
	credentials.cc credentials.hh \
	dbdnsseckeeper.cc \
	digests.hh \
	distributor.hh \
	dns.cc dns.hh \
	dns_random.hh \
	dnsbackend.cc dnsbackend.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnspacket.cc dnspacket.hh \
	dnsparser.cc \
	dnsproxy.cc dnsproxy.hh \
	dnsrecords.cc dnsrecords.hh \
	dnssecinfra.cc dnssecinfra.hh \
	dnsseckeeper.hh \
	dnssecsigner.cc \
	dnswriter.cc \
	dynhandler.cc dynhandler.hh \
	dynlistener.cc dynlistener.hh \
	dynmessenger.hh \
	ednscookies.cc ednscookies.hh \
	ednsoptions.cc ednsoptions.hh \
	ednssubnet.cc ednssubnet.hh \
	gettime.cc gettime.hh \
	gss_context.cc gss_context.hh \
	histogram.hh \
	iputils.cc iputils.hh \
	ixfr.cc ixfr.hh \
	json.cc json.hh \
	lock.hh \
	logger.cc logger.hh \
	logging.hh \
	lua-auth4.cc lua-auth4.hh \
	lua-base4.cc lua-base4.hh \
	misc.cc misc.hh \
	nameserver.cc nameserver.hh \
	namespaces.hh \
	noinitvector.hh \
	nsecrecords.cc \
	opensslsigners.cc opensslsigners.hh \
	packetcache.hh \
	packethandler.cc packethandler.hh \
	pdnsexception.hh \
	proxy-protocol.cc proxy-protocol.hh \
	qtype.cc qtype.hh \
	query-local-address.hh query-local-address.cc \
	rcpgenerator.cc \
	resolver.cc resolver.hh \
	responsestats.cc responsestats.hh responsestats-auth.cc \
	rfc2136handler.cc \
	secpoll-auth.cc secpoll-auth.hh \
	secpoll.cc secpoll.hh \
	serialtweaker.cc \
	sha.hh \
	shuffle.cc shuffle.hh \
	signingpipe.cc signingpipe.hh \
	sillyrecords.cc \
	stat_t.hh \
	statbag.cc statbag.hh \
	stubresolver.cc stubresolver.hh \
	svc-records.cc svc-records.hh \
	tcpreceiver.cc tcpreceiver.hh \
	threadname.hh threadname.cc \
	tkey.cc \
	trusted-notification-proxy.hh trusted-notification-proxy.cc \
	tsigutils.hh tsigutils.cc \
	tsigverifier.cc tsigverifier.hh \
	ueberbackend.cc ueberbackend.hh \
	unix_semaphore.cc \
	unix_utility.cc \
	utility.hh \
	uuid-utils.hh uuid-utils.cc \
	version.cc version.hh \
	views.hh \
	webserver.cc webserver.hh \
	ws-api.cc ws-api.hh \
	ws-auth.cc ws-auth.hh \
	zoneparser-tng.cc

pdns_server_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(DYNLINKFLAGS) \
	$(LIBCRYPTO_LDFLAGS)

EXTRA_pdns_server_DEPENDENCIES = @moduleobjects@
pdns_server_LDADD = \
	@moduleobjects@ \
	@modulelibs@ \
	$(LIBDL) \
	$(YAHTTP_LIBS) \
	$(JSON11_LIBS) \
	$(LIBCRYPTO_LIBS) \
	$(SYSTEMD_LIBS)

if HAVE_LUA_RECORDS
pdns_server_SOURCES += lua-record.cc minicurl.cc minicurl.hh
pdns_server_LDADD += $(LIBCURL)
endif

if LIBSODIUM
pdns_server_SOURCES += sodiumsigners.cc
pdns_server_LDADD += $(LIBSODIUM_LIBS)
endif

if SQLITE3
pdns_server_SOURCES += ssqlite3.cc ssqlite3.hh
pdns_server_LDADD += $(SQLITE3_LIBS)
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
	auth-caches.cc auth-caches.hh \
	auth-catalogzone.cc auth-catalogzone.hh \
	auth-packetcache.cc auth-packetcache.hh \
	auth-querycache.cc auth-querycache.hh \
	auth-zonecache.cc auth-zonecache.hh \
	backends/gsql/gsqlbackend.cc backends/gsql/gsqlbackend.hh \
	backends/gsql/ssql.hh \
	base32.cc \
	base64.cc base64.hh \
	bindlexer.l \
	bindparser.yy \
	cachecleaner.hh \
	check-zone.cc check-zone.hh \
	circular_buffer.hh \
	credentials.cc credentials.hh \
	dbdnsseckeeper.cc \
	dns.cc \
	dnsbackend.cc \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnspacket.cc \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnssecinfra.cc dnssecinfra.hh \
	dnssecsigner.cc \
	dnswriter.cc dnswriter.hh \
	dynlistener.cc \
	ednscookies.cc ednscookies.hh \
	ednsoptions.cc ednsoptions.hh \
	ednssubnet.cc \
	gettime.cc gettime.hh \
	gss_context.cc gss_context.hh \
	ipcipher.cc ipcipher.hh \
	iputils.cc iputils.hh \
	json.cc \
	logger.cc \
	lua-auth4.cc lua-auth4.hh \
	lua-base4.cc lua-base4.hh \
	misc.cc misc.hh \
	nsecrecords.cc \
	opensslsigners.cc opensslsigners.hh \
	pdnsutil.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	serialtweaker.cc \
	shuffle.cc shuffle.hh \
	signingpipe.cc \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	stubresolver.cc stubresolver.hh \
	svc-records.cc svc-records.hh \
	threadname.hh threadname.cc \
	tsigutils.hh tsigutils.cc \
	ueberbackend.cc \
	unix_utility.cc \
	uuid-utils.hh uuid-utils.cc \
	validate.hh \
	zonemd.hh zonemd.cc \
	zoneparser-tng.cc

pdnsutil_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(DYNLINKFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS) \
	$(LIBCRYPTO_LDFLAGS)

EXTRA_pdnsutil_DEPENDENCIES = @moduleobjects@
pdnsutil_LDADD = \
	@moduleobjects@ \
	@modulelibs@ \
	$(YAHTTP_LIBS) \
	$(JSON11_LIBS) \
	$(LIBDL) \
	$(BOOST_PROGRAM_OPTIONS_LIBS) \
	$(LIBCRYPTO_LIBS) \
	$(IPCRYPT_LIBS)

if LIBSODIUM
pdnsutil_SOURCES += sodiumsigners.cc
pdnsutil_LDADD += $(LIBSODIUM_LIBS)
endif

if SQLITE3
pdnsutil_SOURCES += ssqlite3.cc ssqlite3.hh
pdnsutil_LDADD += $(SQLITE3_LIBS)
endif

if PKCS11
pdnsutil_SOURCES +=  pkcs11signers.cc pkcs11signers.hh
pdnsutil_LDADD += $(P11KIT1_LIBS)
endif

if LUA
pdnsutil_LDADD += $(LUA_LIBS)
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
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
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
	svc-records.cc svc-records.hh \
	unix_utility.cc \
	zone2sql.cc \
	zoneparser-tng.cc

zone2sql_LDADD = $(LIBCRYPTO_LIBS) $(JSON11_LIBS)
zone2sql_LDFLAGS = $(AM_LDFLAGS) $(LIBCRYPTO_LDFLAGS)

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
	svc-records.cc svc-records.hh \
	unix_utility.cc \
	zone2json.cc \
	zoneparser-tng.cc

zone2json_LDADD = $(LIBCRYPTO_LIBS) $(JSON11_LIBS)
zone2json_LDFLAGS = $(AM_LDFLAGS) $(LIBCRYPTO_LDFLAGS)

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
	svc-records.cc svc-records.hh \
	unix_utility.cc \
	zone2ldap.cc \
	zoneparser-tng.cc

zone2ldap_LDADD = $(LIBCRYPTO_LIBS)
zone2ldap_LDFLAGS = $(AM_LDFLAGS) $(LIBCRYPTO_LDFLAGS)

if GSS_TSIG
zone2ldap_LDADD += $(GSS_LIBS)
endif

sdig_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dns.cc \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnswriter.cc dnswriter.hh \
	dolog.hh \
	ednscookies.cc ednscookies.hh \
	ednsextendederror.cc ednsextendederror.hh \
	ednssubnet.cc iputils.cc \
	libssl.cc libssl.hh \
	logger.cc \
	misc.cc misc.hh \
	nsecrecords.cc \
	protozero-trace.hh \
	proxy-protocol.cc proxy-protocol.hh \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sdig.cc \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	svc-records.cc svc-records.hh \
	tcpiohandler.cc tcpiohandler.hh \
	unix_utility.cc

sdig_CPPFLAGS = $(AM_CPPFLAGS)
sdig_LDADD = $(LIBCRYPTO_LIBS)
sdig_LDFLAGS = $(AM_LDFLAGS) $(LIBCRYPTO_LDFLAGS)

if HAVE_LIBCURL
sdig_SOURCES += minicurl.cc minicurl.hh
sdig_LDADD += $(LIBCURL)
endif

if HAVE_DNS_OVER_TLS

if HAVE_GNUTLS
sdig_CPPFLAGS += $(GNUTLS_CFLAGS)
sdig_LDADD += -lgnutls
endif

if HAVE_LIBSSL
sdig_CPPFLAGS += $(LIBSSL_CFLAGS)
sdig_LDADD += $(LIBSSL_LIBS)
endif

endif

if LIBSODIUM
sdig_CPPFLAGS +=$(LIBSODIUM_CFLAGS)
sdig_LDADD += $(LIBSODIUM_LIBS)
endif

calidns_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	calidns.cc \
	dns_random.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnswriter.cc dnswriter.hh \
	ednsoptions.cc ednsoptions.hh \
	ednssubnet.cc ednssubnet.hh \
	iputils.cc \
	logger.cc \
	misc.cc misc.hh \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	svc-records.cc svc-records.hh \
	unix_utility.cc

calidns_LDADD = $(LIBCRYPTO_LIBS) \
	$(BOOST_PROGRAM_OPTIONS_LIBS)
calidns_LDFLAGS = $(AM_LDFLAGS) $(THREADFLAGS) $(LIBCRYPTO_LDFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS)

dumresp_SOURCES = \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dumresp.cc \
	iputils.cc iputils.hh \
	logger.cc \
	misc.cc misc.hh \
	qtype.cc \
	statbag.cc \
	unix_utility.cc

dumresp_LDFLAGS = $(AM_LDFLAGS) $(LIBCRYPTO_LDFLAGS)

kvresp_SOURCES = \
	dnslabeltext.cc dnsname.cc dnsname.hh \
	kvresp.cc \
	logger.cc \
	misc.cc misc.hh \
	qtype.cc \
	statbag.cc \
	unix_utility.cc

stubquery_SOURCES = \
	arguments.cc arguments.hh \
	base32.cc \
	base64.cc \
	dnslabeltext.cc \
	dnsname.cc \
	dnsparser.cc \
	dnsrecords.cc \
	dnswriter.cc \
	ednsoptions.cc ednsoptions.hh \
	ednssubnet.cc ednssubnet.hh \
	iputils.cc \
	logger.cc \
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc \
	sillyrecords.cc \
	statbag.cc \
	stubquery.cc \
	stubresolver.cc stubresolver.hh \
	svc-records.cc svc-records.hh \
	unix_utility.cc

stubquery_LDADD = $(LIBCRYPTO_LIBS)
stubquery_LDFLAGS = $(AM_LDFLAGS) $(LIBCRYPTO_LDFLAGS)

saxfr_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dns_random.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnssecinfra.cc \
	dnswriter.cc dnswriter.hh \
	gss_context.cc gss_context.hh \
	iputils.cc \
	logger.cc \
	misc.cc misc.hh \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	saxfr.cc \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	svc-records.cc svc-records.hh \
	unix_utility.cc

saxfr_LDADD = $(LIBCRYPTO_LIBS)
saxfr_LDFLAGS = $(AM_LDFLAGS) $(LIBCRYPTO_LDFLAGS)

if PKCS11
saxfr_SOURCES += pkcs11signers.cc pkcs11signers.hh
saxfr_LDADD += $(P11KIT1_LIBS)
endif

if GSS_TSIG
saxfr_LDADD += $(GSS_LIBS)
endif

ixfrdist_SOURCES = \
	arguments.cc \
	auth-caches.cc auth-caches.hh \
	auth-packetcache.cc auth-packetcache.hh \
	auth-querycache.cc auth-querycache.hh \
	auth-zonecache.cc auth-zonecache.hh \
	axfr-retriever.cc \
	base32.cc \
	base64.cc base64.hh \
	credentials.cc credentials.hh \
	dns.cc \
	dns_random.hh \
	dnsbackend.cc \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnspacket.cc dnspacket.hh \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnssecinfra.cc \
	dnswriter.cc dnswriter.hh \
	ednscookies.cc ednscookies.hh \
	ednsextendederror.cc ednsextendederror.hh \
	ednsoptions.cc ednsoptions.hh \
	ednssubnet.cc ednssubnet.hh \
	gss_context.cc gss_context.hh \
	iputils.hh iputils.cc \
	ixfr.cc ixfr.hh \
	ixfrdist-stats.hh ixfrdist-stats.cc \
	ixfrdist-web.hh ixfrdist-web.cc \
	ixfrdist.cc \
	ixfrutils.cc ixfrutils.hh \
	logger.cc logger.hh\
	misc.cc misc.hh \
	mplexer.hh \
	nsecrecords.cc \
	pollmplexer.cc \
	qtype.cc \
	query-local-address.hh query-local-address.cc \
	rcpgenerator.cc rcpgenerator.hh \
	resolver.cc \
	shuffle.cc shuffle.hh \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	svc-records.cc svc-records.hh \
	threadname.hh threadname.cc \
	tsigverifier.cc tsigverifier.hh \
	ueberbackend.cc ueberbackend.hh \
	unix_utility.cc \
	uuid-utils.hh uuid-utils.cc \
	webserver.hh webserver.cc \
	zoneparser-tng.cc

ixfrdist_LDADD = \
	$(BOOST_PROGRAM_OPTIONS_LIBS) \
	$(JSON11_LIBS) \
	$(LIBDL) \
	$(LIBCRYPTO_LIBS) \
	$(YAHTTP_LIBS) \
	$(YAML_LIBS)

ixfrdist_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS) \
	$(LIBCRYPTO_LDFLAGS)

if LIBSODIUM
ixfrdist_LDADD += $(LIBSODIUM_LIBS)
endif

if PKCS11
ixfrdist_SOURCES += pkcs11signers.cc pkcs11signers.hh
ixfrdist_LDADD += $(P11KIT1_LIBS)
endif

if GSS_TSIG
ixfrdist_LDADD += $(GSS_LIBS)
endif


ixplore_SOURCES = \
	arguments.cc \
	axfr-retriever.cc \
	base32.cc \
	base64.cc base64.hh \
	dns.cc \
	dns_random.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnssecinfra.cc \
	dnswriter.cc dnswriter.hh \
	ednsoptions.cc ednsoptions.hh \
	ednssubnet.cc ednssubnet.hh \
	gss_context.cc gss_context.hh  \
	iputils.cc \
	ixfr.cc ixfr.hh \
	ixfrutils.cc ixfrutils.hh \
	ixplore.cc \
	logger.cc \
	misc.cc misc.hh \
	nsecrecords.cc \
	qtype.cc \
	query-local-address.hh query-local-address.cc \
	rcpgenerator.cc rcpgenerator.hh \
	resolver.cc \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	svc-records.cc svc-records.hh \
	tsigverifier.cc tsigverifier.hh \
	unix_utility.cc zoneparser-tng.cc

ixplore_LDADD = $(LIBCRYPTO_LIBS)
ixplore_LDFLAGS = $(AM_LDFLAGS) $(LIBCRYPTO_LDFLAGS)
if GSS_TSIG
ixplore_LDADD += $(GSS_LIBS)
endif

if PKCS11
ixplore_SOURCES += pkcs11signers.cc pkcs11signers.hh
ixplore_LDADD += $(P11KIT1_LIBS)
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
	iputils.cc \
	logger.cc \
	misc.cc misc.hh \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	svc-records.cc svc-records.hh \
	threadname.hh threadname.cc \
	unix_utility.cc

dnstcpbench_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LIBCRYPTO_LDFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS)

dnstcpbench_LDADD = \
	$(LIBCRYPTO_LIBS) \
	$(BOOST_PROGRAM_OPTIONS_LIBS)

nsec3dig_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnssecinfra.cc \
	dnswriter.cc dnswriter.hh \
	gss_context.cc gss_context.hh \
	iputils.cc \
	logger.cc \
	misc.cc misc.hh \
	nsec3dig.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	svc-records.cc svc-records.hh \
	unix_utility.cc


nsec3dig_LDADD = $(LIBCRYPTO_LIBS)
nsec3dig_LDFLAGS = $(AM_LDFLAGS) $(LIBCRYPTO_LDFLAGS)

if GSS_TSIG
nsec3dig_LDADD += $(GSS_LIBS)
endif

if PKCS11
nsec3dig_SOURCES += pkcs11signers.cc pkcs11signers.hh
nsec3dig_LDADD += $(P11KIT1_LIBS)
endif

tsig_tests_SOURCES = \
	arguments.cc \
	axfr-retriever.cc \
	base32.cc \
	base64.cc base64.hh \
	digests.hh \
	dns.cc \
	dns_random.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnssecinfra.cc \
	dnswriter.cc dnswriter.hh \
	gss_context.cc gss_context.hh \
	iputils.cc \
	logger.cc \
	misc.cc misc.hh \
	nsecrecords.cc \
	qtype.cc \
	query-local-address.cc \
	rcpgenerator.cc rcpgenerator.hh \
	resolver.cc \
	sillyrecords.cc \
	sstuff.hh \
	statbag.cc \
	svc-records.cc svc-records.hh \
	tsig-tests.cc \
	tsigverifier.cc tsigverifier.hh \
	unix_utility.cc

tsig_tests_LDADD = $(LIBCRYPTO_LIBS)
tsig_tests_LDFLAGS = $(AM_LDFLAGS) $(LIBCRYPTO_LDFLAGS)

if PKCS11
tsig_tests_SOURCES += pkcs11signers.cc pkcs11signers.hh
tsig_tests_LDADD += $(P11KIT1_LIBS)
endif

if GSS_TSIG
tsig_tests_LDADD += $(GSS_LIBS)
endif

speedtest_SOURCES = \
	arguments.cc arguments.hh \
	base32.cc \
	base64.cc base64.hh \
	credentials.cc credentials.hh \
	dns_random.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc \
	dnssecinfra.cc dnssecinfra.hh \
	dnswriter.cc dnswriter.hh \
	gss_context.cc gss_context.hh \
	iputils.cc \
	logger.cc \
	misc.cc misc.hh \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	shuffle.cc shuffle.hh \
	sillyrecords.cc \
	speedtest.cc \
	statbag.cc \
	svc-records.cc svc-records.hh \
	unix_utility.cc \
	uuid-utils.cc

speedtest_LDFLAGS = $(AM_LDFLAGS) $(LIBCRYPTO_LDFLAGS)
speedtest_LDADD = $(LIBCRYPTO_LIBS) \
	$(RT_LIBS)

dnswasher_SOURCES = \
	base64.cc \
	dnslabeltext.cc \
	dnsname.hh dnsname.cc \
	dnsparser.hh \
	dnspcap.cc dnspcap.hh \
	dnswasher.cc \
	dnswriter.hh \
	ipcipher.cc ipcipher.hh \
	logger.cc \
	misc.cc \
	qtype.cc \
	statbag.cc \
	unix_utility.cc

dnswasher_LDFLAGS =	$(AM_LDFLAGS) $(BOOST_PROGRAM_OPTIONS_LDFLAGS) $(LIBCRYPTO_LDFLAGS)
dnswasher_LDADD =	$(BOOST_PROGRAM_OPTIONS_LIBS) $(LIBCRYPTO_LIBS) $(IPCRYPT_LIBS)

dnsbulktest_SOURCES = \
	arguments.cc arguments.hh \
	base32.cc \
	base64.cc \
	dns_random.hh \
	dnsbulktest.cc \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc \
	dnsrecords.cc \
	dnswriter.cc \
	iputils.cc iputils.hh \
	logger.cc \
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc \
	sillyrecords.cc \
	statbag.cc \
	svc-records.cc svc-records.hh \
	unix_utility.cc

dnsbulktest_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LIBCRYPTO_LDFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS)

dnsbulktest_LDADD = \
	$(LIBCRYPTO_LIBS) \
	$(BOOST_PROGRAM_OPTIONS_LIBS)

comfun_SOURCES = \
	base32.cc \
	base64.cc \
	comfun.cc \
	dns.cc \
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
	svc-records.cc svc-records.hh \
	unix_utility.cc \
	zoneparser-tng.cc zoneparser-tng.hh

comfun_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LIBCRYPTO_LDFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS)

comfun_LDADD = \
	$(LIBCRYPTO_LIBS) \
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
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	statbag.cc \
	svc-records.cc svc-records.hh \
	unix_utility.cc \
	utility.hh

dnsscan_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LIBCRYPTO_LDFLAGS)

dnsscan_LDADD = $(LIBCRYPTO_LIBS)

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
	ednsoptions.cc ednsoptions.hh \
	ednssubnet.cc ednssubnet.hh \
	iputils.cc \
	logger.cc \
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	statbag.cc \
	svc-records.cc svc-records.hh \
	unix_utility.cc \
	utility.hh

dnsreplay_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LIBCRYPTO_LDFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS)

dnsreplay_LDADD = \
	$(LIBCRYPTO_LIBS) \
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
	misc.cc \
	mplexer.hh \
	nproxy.cc \
	nsecrecords.cc \
	pollmplexer.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	statbag.cc \
	svc-records.cc svc-records.hh \
	unix_utility.cc

nproxy_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LIBCRYPTO_LDFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS)

nproxy_LDADD = \
	$(LIBCRYPTO_LIBS) \
	$(BOOST_PROGRAM_OPTIONS_LIBS)

pdns_notify_SOURCES = \
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
	misc.cc \
	notify.cc \
	nsecrecords.cc \
	pollmplexer.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	statbag.cc \
	svc-records.cc svc-records.hh \
	unix_utility.cc

pdns_notify_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LIBCRYPTO_LDFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS)

pdns_notify_LDADD = \
	$(LIBCRYPTO_LIBS) \
	$(BOOST_PROGRAM_OPTIONS_LIBS)

if LIBSODIUM
pdns_notify_LDADD += $(LIBSODIUM_LIBS)
dnsbulktest_LDADD += $(LIBSODIUM_LIBS)
endif

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
	histog.hh \
	logger.cc \
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	statbag.cc \
	statnode.cc statnode.hh \
	svc-records.cc svc-records.hh \
	unix_utility.cc \
	utility.hh

dnsscope_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LIBCRYPTO_LDFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS)

dnsscope_LDADD = \
	$(LIBCRYPTO_LIBS) \
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
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	statbag.cc \
	svc-records.cc svc-records.hh \
	unix_utility.cc \
	utility.hh

dnsgram_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LIBCRYPTO_LDFLAGS)

dnsgram_LDADD = \
	$(LIBCRYPTO_LIBS)

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
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	statbag.cc \
	svc-records.cc svc-records.hh \
	unix_utility.cc \
	utility.hh

dnsdemog_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LIBCRYPTO_LDFLAGS)

dnsdemog_LDADD = \
	$(LIBCRYPTO_LIBS)

dnspcap2calidns_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnspcap.cc dnspcap.hh \
	dnspcap2calidns.cc \
	dnsrecords.cc \
	dnswriter.cc dnswriter.hh \
	ednsoptions.cc ednsoptions.hh \
	ednssubnet.cc ednssubnet.hh \
	iputils.cc \
	logger.cc \
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	statbag.cc \
	svc-records.cc svc-records.hh \
	unix_utility.cc \
	utility.hh

dnspcap2calidns_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LIBCRYPTO_LDFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS)

dnspcap2calidns_LDADD = \
	$(LIBCRYPTO_LIBS) \
	$(BOOST_PROGRAM_OPTIONS_LIBS)

dnspcap2protobuf_SOURCES = \
	base32.cc \
	base64.cc base64.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnspcap.cc dnspcap.hh \
	dnspcap2protobuf.cc \
	dnsrecords.cc \
	dnswriter.cc dnswriter.hh \
	gettime.cc gettime.hh \
	iputils.cc \
	logger.cc \
	misc.cc \
	nsecrecords.cc \
	protozero.cc protozero.hh \
	qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	statbag.cc \
	svc-records.cc svc-records.hh \
	unix_utility.cc \
	utility.hh \
	uuid-utils.hh uuid-utils.cc

dnspcap2protobuf_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LIBCRYPTO_LDFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS)

dnspcap2protobuf_LDADD = \
	$(LIBCRYPTO_LIBS) \
	$(BOOST_PROGRAM_OPTIONS_LIBS) \
	$(RT_LIBS)

pdns.conf-dist: pdns_server
	$(AM_V_GEN)./pdns_server --config=default > $@

testrunner_SOURCES = \
	arguments.cc \
	auth-caches.cc auth-caches.hh \
	auth-packetcache.cc auth-packetcache.hh \
	auth-querycache.cc auth-querycache.hh \
	auth-zonecache.cc auth-zonecache.hh \
	base32.cc \
	base64.cc \
	bindlexer.l \
	bindparser.yy \
	channel.cc channel.hh \
	credentials.cc credentials.hh \
	dbdnsseckeeper.cc \
	dns.cc \
	dnsbackend.cc \
	dnslabeltext.cc \
	dnsname.cc \
	dnsname.hh \
	dnspacket.cc \
	dnsparser.hh dnsparser.cc \
	dnsrecords.cc \
	dnssecinfra.cc \
	dnssecsigner.cc \
	dnswriter.cc \
	ednscookies.cc ednscookies.hh \
	ednsoptions.cc ednsoptions.hh \
	ednssubnet.cc \
	gettime.cc gettime.hh \
	gss_context.cc gss_context.hh \
	histogram.hh \
	ipcipher.cc ipcipher.hh \
	iputils.cc \
	ixfr.cc ixfr.hh \
	logger.cc \
	lua-auth4.hh lua-auth4.cc \
	lua-base4.hh lua-base4.cc \
	misc.cc \
	nameserver.cc \
	nsecrecords.cc \
	opensslsigners.cc opensslsigners.hh \
	pollmplexer.cc \
	proxy-protocol.cc proxy-protocol.hh \
	qtype.cc \
	rcpgenerator.cc \
	responsestats-auth.cc \
	responsestats.cc responsestats.hh \
	shuffle.cc shuffle.hh \
	sillyrecords.cc \
	stat_t.hh \
	statbag.cc \
	stubresolver.hh stubresolver.cc \
	svc-records.cc svc-records.hh \
	test-arguments_cc.cc \
	test-auth-zonecache_cc.cc \
	test-base32_cc.cc \
	test-base64_cc.cc \
	test-bindparser_cc.cc \
	test-channel.cc \
	test-common.hh \
	test-communicator_hh.cc \
	test-credentials_cc.cc \
	test-digests_hh.cc \
	test-distributor_hh.cc \
	test-dns_cc.cc \
	test-dns_random_hh.cc \
	test-dnsname_cc.cc \
	test-dnsparser_cc.cc \
	test-dnsparser_hh.cc \
	test-dnsrecordcontent.cc \
	test-dnsrecords_cc.cc \
	test-dnswriter_cc.cc \
	test-ednscookie_cc.cc \
	test-ipcrypt_cc.cc \
	test-iputils_hh.cc \
	test-ixfr_cc.cc \
	test-lock_hh.cc \
	test-lua_auth4_cc.cc \
	test-luawrapper.cc \
	test-misc_hh.cc \
	test-mplexer.cc \
	test-nameserver_cc.cc \
	test-packetcache_cc.cc \
	test-packetcache_hh.cc \
	test-proxy_protocol_cc.cc \
	test-rcpgenerator_cc.cc \
	test-sha_hh.cc \
	test-signers.cc \
	test-statbag_cc.cc \
	test-svc_records_cc.cc \
	test-trusted-notification-proxy_cc.cc \
	test-tsig.cc \
	test-ueberbackend_cc.cc \
	test-webserver_cc.cc \
	test-zonemd_cc.cc \
	test-zoneparser_tng_cc.cc \
	testrunner.cc \
	threadname.hh threadname.cc \
	trusted-notification-proxy.cc \
	tsigverifier.cc tsigverifier.hh \
	ueberbackend.cc ueberbackend.hh \
	unix_utility.cc \
	uuid-utils.cc \
	validate.hh \
	webserver.cc \
	zonemd.cc zonemd.hh \
	zoneparser-tng.cc zoneparser-tng.hh

testrunner_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LIBCRYPTO_LDFLAGS) \
	$(BOOST_UNIT_TEST_FRAMEWORK_LDFLAGS)

testrunner_LDADD = \
	$(LIBCRYPTO_LIBS) \
	$(BOOST_UNIT_TEST_FRAMEWORK_LIBS) \
	$(RT_LIBS) \
	$(LUA_LIBS) \
	$(LIBDL) \
	$(IPCRYPT_LIBS) \
	$(YAHTTP_LIBS) \
	$(JSON11_LIBS)

if GSS_TSIG
testrunner_LDADD += $(GSS_LIBS)
speedtest_LDADD += $(GSS_LIBS)
endif

if PKCS11
testrunner_SOURCES += pkcs11signers.cc pkcs11signers.hh
testrunner_LDADD += $(P11KIT1_LIBS)
speedtest_SOURCES += pkcs11signers.cc pkcs11signers.hh
speedtest_LDADD += $(P11KIT1_LIBS)
endif

if LIBSODIUM
testrunner_SOURCES += sodiumsigners.cc
testrunner_LDADD += $(LIBSODIUM_LIBS)
speedtest_LDADD += $(LIBSODIUM_LIBS)
endif

if HAVE_FREEBSD
ixfrdist_SOURCES += kqueuemplexer.cc
testrunner_SOURCES += kqueuemplexer.cc
endif

if HAVE_OPENBSD
ixfrdist_SOURCES += kqueuemplexer.cc
testrunner_SOURCES += kqueuemplexer.cc
endif

if HAVE_LINUX
ixfrdist_SOURCES += epollmplexer.cc
testrunner_SOURCES += epollmplexer.cc
endif

if HAVE_SOLARIS
ixfrdist_SOURCES += \
	devpollmplexer.cc \
	portsmplexer.cc
testrunner_SOURCES += \
	devpollmplexer.cc \
	portsmplexer.cc
endif

pdns_control_SOURCES = \
	arguments.cc \
	dnslabeltext.cc \
	dnsname.cc \
	dynloader.cc \
	dynmessenger.cc \
	logger.cc \
	misc.cc \
	qtype.cc \
	statbag.cc \
	unix_utility.cc

pdns_control_LDFLAGS = \
       $(AM_LDFLAGS) \
       $(LIBCRYPTO_LDFLAGS)

noinst_PROGRAMS = speedtest tsig_tests

if UNIT_TESTS
noinst_PROGRAMS += testrunner
TESTS_ENVIRONMENT = env BOOST_TEST_LOG_LEVEL=message BOOST_TEST_RANDOM=1 SRCDIR='$(srcdir)'
TESTS=testrunner

else
check-local:
	@echo "Unit tests are not enabled"
	@echo "Run ./configure --enable-unit-tests"
endif

if FUZZ_TARGETS

LIB_FUZZING_ENGINE ?= standalone_fuzz_target_runner.o

standalone_fuzz_target_runner.o: standalone_fuzz_target_runner.cc

fuzz_targets_programs =  \
	fuzz_target_moadnsparser \
	fuzz_target_packetcache \
	fuzz_target_proxyprotocol \
	fuzz_target_dnslabeltext_parseRFC1035CharString \
	fuzz_target_yahttp \
	fuzz_target_zoneparsertng

fuzz_targets: $(ARC4RANDOM_LIBS) $(fuzz_targets_programs)

bin_PROGRAMS += \
	$(fuzz_targets_programs)

fuzz_targets_libs = \
	$(LIBCRYPTO_LIBS) \
	$(LIB_FUZZING_ENGINE)
fuzz_targets_ldflags = \
	$(AM_LDFLAGS) \
	$(DYNLINKFLAGS) \
	$(LIBCRYPTO_LDFLAGS) \
	$(FUZZING_LDFLAGS)

# we need the mockup runner to be built, but not linked if a real fuzzing engine is used
fuzz_targets_deps = standalone_fuzz_target_runner.o

fuzz_target_moadnsparser_SOURCES = \
	base32.cc base32.hh \
	base64.cc base64.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc dnsrecords.hh \
	dnswriter.cc dnswriter.hh \
	fuzz_moadnsparser.cc \
	logger.cc logger.hh \
	misc.cc misc.hh \
	nsecrecords.cc  \
	qtype.cc qtype.hh \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	statbag.cc statbag.hh \
	svc-records.cc svc-records.hh \
	unix_utility.cc \
	utility.hh

fuzz_target_moadnsparser_DEPENDENCIES = $(fuzz_targets_deps)
fuzz_target_moadnsparser_LDFLAGS = $(fuzz_targets_ldflags)
fuzz_target_moadnsparser_LDADD = $(fuzz_targets_libs)

fuzz_target_packetcache_SOURCES = \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	ednsoptions.cc ednsoptions.hh \
	fuzz_packetcache.cc \
	misc.cc misc.hh \
	packetcache.hh \
	qtype.cc qtype.hh \
	statbag.cc statbag.hh \
	svc-records.cc svc-records.hh

fuzz_target_packetcache_DEPENDENCIES = $(fuzz_targets_deps)
fuzz_target_packetcache_LDFLAGS = $(fuzz_targets_ldflags)
fuzz_target_packetcache_LDADD = $(fuzz_targets_libs)

fuzz_target_proxyprotocol_SOURCES = \
	fuzz_proxyprotocol.cc \
	iputils.hh \
	proxy-protocol.cc \
	proxy-protocol.hh

fuzz_target_proxyprotocol_DEPENDENCIES = $(fuzz_targets_deps)
fuzz_target_proxyprotocol_LDFLAGS = $(fuzz_targets_ldflags)
fuzz_target_proxyprotocol_LDADD = $(fuzz_targets_libs)

fuzz_target_yahttp_SOURCES = \
	fuzz_yahttp.cc

fuzz_target_yahttp_DEPENDENCIES = $(fuzz_targets_deps)
fuzz_target_yahttp_LDFLAGS = $(fuzz_targets_ldflags)
fuzz_target_yahttp_LDADD = $(fuzz_targets_libs) \
	$(YAHTTP_LIBS)

fuzz_target_zoneparsertng_SOURCES = \
	base32.cc base32.hh \
	base64.cc base64.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc dnsrecords.hh \
	dnswriter.cc dnswriter.hh \
	fuzz_zoneparsertng.cc \
	logger.cc logger.hh \
	misc.cc misc.hh \
	nsecrecords.cc  \
	qtype.cc qtype.hh \
	rcpgenerator.cc rcpgenerator.hh \
	sillyrecords.cc \
	statbag.cc statbag.hh \
	svc-records.cc svc-records.hh \
	unix_utility.cc \
	utility.hh \
	zoneparser-tng.cc zoneparser-tng.hh

fuzz_target_zoneparsertng_DEPENDENCIES = $(fuzz_targets_deps)
fuzz_target_zoneparsertng_LDFLAGS = $(fuzz_targets_ldflags)
fuzz_target_zoneparsertng_LDADD = $(fuzz_targets_libs)

fuzz_target_dnslabeltext_parseRFC1035CharString_SOURCES = \
	dnslabeltext.cc \
	fuzz_dnslabeltext_parseRFC1035CharString.cc

fuzz_target_dnslabeltext_parseRFC1035CharString_DEPENDENCIES = $(fuzz_targets_deps)
fuzz_target_dnslabeltext_parseRFC1035CharString_LDFLAGS = $(fuzz_targets_ldflags)
fuzz_target_dnslabeltext_parseRFC1035CharString_LDADD = $(fuzz_targets_libs)

endif

dnslabeltext.cc: dnslabeltext.rl
	$(AM_V_GEN)$(RAGEL) $< -o dnslabeltext.cc

bind-dnssec.schema.sqlite3.sql.h: bind-dnssec.schema.sqlite3.sql
	( echo '#pragma once'; echo 'static char sqlCreate[] __attribute__((unused))=' ; sed 's/$$/"/g' $< | sed 's/^/"/g'  ; echo ';' ) > $@

bindlexer.$(OBJEXT): bindparser.hh

pdns_recursor rec_control:
	@echo "Please build the recursor from the recursordist/ dir"
	@exit 1

dnsdist:
	@echo "Please build dnsdist from the dnsdistdist/ dir"
	@exit 1

if HAVE_SYSTEMD
pdns.service: pdns.service.in
	$(AM_V_GEN)sed -e 's![@]sbindir[@]!$(sbindir)!' -e 's![@]service_user[@]!$(service_user)!' -e 's![@]service_group[@]!$(service_group)!' < $< > $@
if !HAVE_SYSTEMD_WITH_RUNTIME_DIR_ENV
if HAVE_SYSTEMD_PERCENT_T
	$(AM_V_GEN)sed -e 's!/pdns_server!& --socket-dir=%t/pdns!' -i $@
endif
endif
if !HAVE_SYSTEMD_LOCK_PERSONALITY
	$(AM_V_GEN)perl -ni -e 'print unless /^LockPersonality/' $@
endif
if !HAVE_SYSTEMD_PRIVATE_DEVICES
	$(AM_V_GEN)perl -ni -e 'print unless /^PrivateDevices/' $@
endif
if !HAVE_SYSTEMD_PRIVATE_TMP
	$(AM_V_GEN)perl -ni -e 'print unless /^PrivateTmp/' $@
endif
if !HAVE_SYSTEMD_PRIVATE_USERS
	$(AM_V_GEN)perl -ni -e 'print unless /^PrivateUsers/' $@
endif
if !HAVE_SYSTEMD_PROTECT_CLOCK
	$(AM_V_GEN)perl -ni -e 'print unless /^ProtectClock/' $@
endif
if !HAVE_SYSTEMD_PROTECT_CONTROL_GROUPS
	$(AM_V_GEN)perl -ni -e 'print unless /^ProtectControlGroups/' $@
endif
if !HAVE_SYSTEMD_PROTECT_HOME
	$(AM_V_GEN)perl -ni -e 'print unless /^ProtectHome/' $@
endif
if !HAVE_SYSTEMD_PROTECT_HOSTNAME
	$(AM_V_GEN)perl -ni -e 'print unless /^ProtectHostname/' $@
endif
if !HAVE_SYSTEMD_PROTECT_KERNEL_LOGS
	$(AM_V_GEN)perl -ni -e 'print unless /^ProtectKernelLogs/' $@
endif
if !HAVE_SYSTEMD_PROTECT_KERNEL_MODULES
	$(AM_V_GEN)perl -ni -e 'print unless /^ProtectKernelModules/' $@
endif
if !HAVE_SYSTEMD_PROTECT_KERNEL_TUNABLES
	$(AM_V_GEN)perl -ni -e 'print unless /^ProtectKernelTunables/' $@
endif
if !HAVE_SYSTEMD_PROTECT_SYSTEM
	$(AM_V_GEN)perl -ni -e 'print unless /^ProtectSystem/' $@
endif
if !HAVE_SYSTEMD_RESTRICT_ADDRESS_FAMILIES
	$(AM_V_GEN)perl -ni -e 'print unless /^RestrictAddressFamilies/' $@
endif
if !HAVE_SYSTEMD_RESTRICT_NAMESPACES
	$(AM_V_GEN)perl -ni -e 'print unless /^RestrictNamespaces/' $@
endif
if !HAVE_SYSTEMD_RESTRICT_REALTIME
	$(AM_V_GEN)perl -ni -e 'print unless /^RestrictRealtime/' $@
endif
if !HAVE_SYSTEMD_RESTRICT_SUIDSGID
	$(AM_V_GEN)perl -ni -e 'print unless /^RestrictSUIDSGID/' $@
endif
if !HAVE_SYSTEMD_SYSTEM_CALL_ARCHITECTURES
	$(AM_V_GEN)perl -ni -e 'print unless /^SystemCallArchitectures/' $@
endif
if !HAVE_SYSTEMD_SYSTEM_CALL_FILTER
	$(AM_V_GEN)perl -ni -e 'print unless /^SystemCallFilter/' $@
endif
if !HAVE_SYSTEMD_PROTECT_PROC
	$(AM_V_GEN)perl -ni -e 'print unless /^ProtectProc/' $@
endif
if !HAVE_SYSTEMD_PRIVATE_IPC
	$(AM_V_GEN)perl -ni -e 'print unless /^PrivateIPC/' $@
endif
if !HAVE_SYSTEMD_REMOVE_IPC
	$(AM_V_GEN)perl -ni -e 'print unless /^RemoveIPC/' $@
endif

pdns@.service: pdns.service
	$(AM_V_GEN)sed -e 's!/pdns_server!& --config-name=%i!' \
	  -e 's!Authoritative Server!& %i!' \
	  -e 's!SyslogIdentifier=.*!&-%i!' \
	  < $< > $@
if HAVE_SYSTEMD_PERCENT_T
	$(AM_V_GEN)sed -e 's!RuntimeDirectory=.*!&-%i!' -i $@
if !HAVE_SYSTEMD_WITH_RUNTIME_DIR_ENV
	$(AM_V_GEN)sed -e 's!--socket-dir=[^ ]\+!&-%i !' -i $@
endif
endif

systemdsystemunitdir = $(SYSTEMD_DIR)

systemdsystemunit_DATA = \
	pdns.service \
	pdns@.service

CLEANFILES += \
	pdns.service \
	pdns@.service

if IXFRDIST
ixfrdist.service: ixfrdist.service.in
	$(AM_V_GEN)sed -e 's![@]bindir[@]!$(bindir)!' < $< > $@
if !HAVE_SYSTEMD_LOCK_PERSONALITY
	$(AM_V_GEN)perl -ni -e 'print unless /^LockPersonality/' $@
endif
if !HAVE_SYSTEMD_PRIVATE_DEVICES
	$(AM_V_GEN)perl -ni -e 'print unless /^PrivateDevices/' $@
endif
if !HAVE_SYSTEMD_PRIVATE_TMP
	$(AM_V_GEN)perl -ni -e 'print unless /^PrivateTmp/' $@
endif
if !HAVE_SYSTEMD_PRIVATE_USERS
	$(AM_V_GEN)perl -ni -e 'print unless /^PrivateUsers/' $@
endif
if !HAVE_SYSTEMD_PROTECT_CLOCK
	$(AM_V_GEN)perl -ni -e 'print unless /^ProtectClock/' $@
endif
if !HAVE_SYSTEMD_PROTECT_CONTROL_GROUPS
	$(AM_V_GEN)perl -ni -e 'print unless /^ProtectControlGroups/' $@
endif
if !HAVE_SYSTEMD_PROTECT_HOME
	$(AM_V_GEN)perl -ni -e 'print unless /^ProtectHome/' $@
endif
if !HAVE_SYSTEMD_PROTECT_HOSTNAME
	$(AM_V_GEN)perl -ni -e 'print unless /^ProtectHostname/' $@
endif
if !HAVE_SYSTEMD_PROTECT_KERNEL_LOGS
	$(AM_V_GEN)perl -ni -e 'print unless /^ProtectKernelLogs/' $@
endif
if !HAVE_SYSTEMD_PROTECT_KERNEL_MODULES
	$(AM_V_GEN)perl -ni -e 'print unless /^ProtectKernelModules/' $@
endif
if !HAVE_SYSTEMD_PROTECT_KERNEL_TUNABLES
	$(AM_V_GEN)perl -ni -e 'print unless /^ProtectKernelTunables/' $@
endif
if !HAVE_SYSTEMD_PROTECT_SYSTEM
	$(AM_V_GEN)perl -ni -e 'print unless /^ProtectSystem/' $@
endif
if !HAVE_SYSTEMD_RESTRICT_ADDRESS_FAMILIES
	$(AM_V_GEN)perl -ni -e 'print unless /^RestrictAddressFamilies/' $@
endif
if !HAVE_SYSTEMD_RESTRICT_NAMESPACES
	$(AM_V_GEN)perl -ni -e 'print unless /^RestrictNamespaces/' $@
endif
if !HAVE_SYSTEMD_RESTRICT_REALTIME
	$(AM_V_GEN)perl -ni -e 'print unless /^RestrictRealtime/' $@
endif
if !HAVE_SYSTEMD_RESTRICT_SUIDSGID
	$(AM_V_GEN)perl -ni -e 'print unless /^RestrictSUIDSGID/' $@
endif
if !HAVE_SYSTEMD_SYSTEM_CALL_ARCHITECTURES
	$(AM_V_GEN)perl -ni -e 'print unless /^SystemCallArchitectures/' $@
endif
if !HAVE_SYSTEMD_SYSTEM_CALL_FILTER
	$(AM_V_GEN)perl -ni -e 'print unless /^SystemCallFilter/' $@
endif
if !HAVE_SYSTEMD_PROTECT_PROC
	$(AM_V_GEN)perl -ni -e 'print unless /^ProtectProc/' $@
endif
if !HAVE_SYSTEMD_MEMORY_DENY_WRITE_EXECUTE
	$(AM_V_GEN)perl -ni -e 'print unless /^MemoryDenyWriteExecute/' $@
endif
if !HAVE_SYSTEMD_PRIVATE_IPC
	$(AM_V_GEN)perl -ni -e 'print unless /^PrivateIPC/' $@
endif
if !HAVE_SYSTEMD_REMOVE_IPC
	$(AM_V_GEN)perl -ni -e 'print unless /^RemoveIPC/' $@
endif

ixfrdist@.service: ixfrdist.service
	$(AM_V_GEN)sed -e 's!/ixfrdist!& --config $(sysconfdir)/ixfrdist-%i.yml!' \
	  < $< > $@

systemdsystemunit_DATA += \
	ixfrdist.service \
	ixfrdist@.service
endif # IXFRDIST

CLEANFILES += \
	ixfrdist.service \
	ixfrdist@.service

endif # HAVE_SYSTEMD
