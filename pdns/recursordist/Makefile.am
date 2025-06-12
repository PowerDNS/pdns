JSON11_LIBS = $(top_builddir)/ext/json11/libjson11.la
PROBDS_LIBS = $(top_builddir)/ext/probds/libprobds.la
ARC4RANDOM_LIBS = $(top_builddir)/ext/arc4random/libarc4random.la
RUST_LIBS = $(top_builddir)/rec-rust-lib/rust/librecrust.a $(LIBDL)

AM_CPPFLAGS = $(LUA_CFLAGS) $(YAHTTP_CFLAGS) $(BOOST_CPPFLAGS) $(LIBSODIUM_CFLAGS) $(NET_SNMP_CFLAGS) $(LIBCAP_CFLAGS) $(SANITIZER_FLAGS) -O3 -Wall -pthread -DSYSCONFDIR=\"${sysconfdir}\" $(SYSTEMD_CFLAGS)

AM_CPPFLAGS += \
	-I$(top_srcdir)/ext/json11 \
	-I$(top_srcdir)/ext/protozero/include \
	-I$(top_srcdir)/rec-rust-lib \
	-I$(top_builddir)/rec-rust-lib \
	-I$(top_srcdir)/rec-rust-lib/rust/src \
	$(YAHTTP_CFLAGS) \
	$(LIBCRYPTO_INCLUDES) \
	-DBOOST_CONTAINER_USE_STD_EXCEPTIONS

AM_CXXFLAGS = \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DPKGLIBDIR=\"$(pkglibdir)\" \
	-DLOCALSTATEDIR=\"$(socketdir)\"

AM_CXXFLAGS += \
	-DNODCACHEDIRNOD=\"$(nodcachedir)/nod\" -DNODCACHEDIRUDR=\"$(nodcachedir)/udr\"

if FSTRM
AM_CPPFLAGS += \
	$(FSTRM_CFLAGS)
endif

AM_LDFLAGS = \
	$(PROGRAM_LDFLAGS) \
	$(THREADFLAGS)

ACLOCAL_AMFLAGS = -I m4

BUILT_SOURCES=htmlfiles.h \
	dnslabeltext.cc \
	rec-metrics-gen.h \
	rec-prometheus-gen.h \
	rec-snmp-gen.h \
	rec-oids-gen.h \
	RECURSOR-MIB.txt

CLEANFILES = htmlfiles.h \
	recursor.yml-dist

htmlfiles.h: incfiles ${srcdir}/html/* ${srcdir}/html/js/*
	$(AM_V_GEN)$(srcdir)/incfiles > $@.tmp
	@mv $@.tmp $@

# Use patterns to avoid having two instances of generate run simultaneously, a well-known hack for GNU make
rec-metrics-gen%h rec-prometheus-gen%h rec-snmp-gen%h rec-oids-gen%h RECURSOR-MIB%txt: metrics.py metrics_table.py RECURSOR-MIB.in
	$(PYTHON) metrics.py

# We explicitly build rec-rust-lib in two steps, as it modifies files in the rec-rust-lib/rust subdir
SUBDIRS=ext rec-rust-lib rec-rust-lib/rust

if LUA
AM_CPPFLAGS +=$(LUA_CFLAGS)
endif

EXTRA_DIST = \
	contrib/* \
	COPYING \
	devpollmplexer.cc \
	dnslabeltext.cc \
	dnslabeltext.rl \
	dnsmessage.proto \
	effective_tld_names.dat \
	epollmplexer.cc \
	kqueuemplexer.cc \
	lua_hpp.mk \
	malloctrace.cc malloctrace.hh \
	mkpubsuffixcc \
	NOTICE \
	opensslsigners.hh opensslsigners.cc \
	portsmplexer.cc \
	dnstap.proto dnstap.cc dnstap.hh fstrm_logger.cc fstrm_logger.hh \
	ext/protozero/include/* \
	rrd/* \
	html incfiles \
	test_libcrypto \
	pdns-recursor.service.in \
	RECURSOR-MIB.txt \
	metrics.py \
	metrics_table.py \
	RECURSOR-MIB.in \
	rec-metrics-gen.h \
	rec-prometheus-gen.h \
	rec-snmp-gen.h \
	rec-oids-gen.h \
	builder-support/gen-version

dist-hook:
	for file in $$(find $(distdir)/docs -type l); do \
	  t=`stat -c%N $$file | awk '{print $$NF}' | sed "s/'//g"` ; \
	  ln -fs ../$$t $$file; \
	done

sbin_PROGRAMS = pdns_recursor
bin_PROGRAMS = rec_control

TESTS=test_libcrypto

if UNIT_TESTS
noinst_PROGRAMS = testrunner
TESTS_ENVIRONMENT = env BOOST_TEST_LOG_LEVEL=message BOOST_TEST_RANDOM=1 SRCDIR='$(srcdir)'
TESTS += testrunner
else
check-local:
	@echo "Unit tests are not enabled"
	@echo "Run ./configure --enable-unit-tests"
endif

pdns_recursor_SOURCES = \
	aggressive_nsec.cc aggressive_nsec.hh \
	arguments.cc \
	auth-catalogzone.hh \
	axfr-retriever.hh axfr-retriever.cc \
	base32.cc base32.hh \
	base64.cc base64.hh \
	burtle.hh \
	cachecleaner.hh \
	capabilities.cc capabilities.hh \
	channel.cc channel.hh \
	circular_buffer.hh \
	comment.hh \
	coverage.cc coverage.hh \
	credentials.cc credentials.hh \
	dns.hh dns.cc \
	dns_random.hh \
	dnsbackend.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnspacket.hh \
	dnsparser.hh dnsparser.cc \
	dnsrecords.cc dnsrecords.hh \
	dnssecinfra.hh dnssecinfra.cc \
	dnsseckeeper.hh \
	dnswriter.cc dnswriter.hh \
	dolog.hh \
	ednscookies.cc ednscookies.hh \
	ednsextendederror.cc ednsextendederror.hh \
	ednsoptions.cc ednsoptions.hh \
	ednspadding.cc ednspadding.hh \
	ednssubnet.cc ednssubnet.hh \
	filterpo.cc filterpo.hh \
	fstrm_logger.cc fstrm_logger.hh \
	gettime.cc gettime.hh \
	gss_context.cc gss_context.hh \
	histogram.hh \
	iputils.hh iputils.cc \
	ixfr.cc ixfr.hh \
	json.cc json.hh \
	lazy_allocator.hh \
	libssl.cc libssl.hh \
	lock.hh \
	logger.hh logger.cc \
	logging.hh logging.cc logr.hh \
	lua-base4.cc lua-base4.hh \
	lua-recursor4-ffi.hh \
	lua-recursor4.cc lua-recursor4.hh \
	lwres.cc lwres.hh \
	misc.hh misc.cc \
	mplexer.hh \
	mtasker.hh \
	mtasker_context.cc mtasker_context.hh \
	namespaces.hh \
	negcache.hh negcache.cc \
	noinitvector.hh \
	nsecrecords.cc \
	opensslsigners.cc opensslsigners.hh \
	packetcache.hh \
	pdns_recursor.cc \
	pdnsexception.hh \
	pollmplexer.cc \
	protozero-trace.cc protozero-trace.hh \
	protozero.cc protozero.hh \
	proxy-protocol.cc proxy-protocol.hh \
	pubsuffix.hh pubsuffix.cc \
	pubsuffixloader.cc \
	qtype.hh qtype.cc \
	query-local-address.hh query-local-address.cc \
	ratelimitedlog.hh \
	rcpgenerator.cc rcpgenerator.hh \
	rec-carbon.cc \
	rec-eventtrace.cc rec-eventtrace.hh \
	rec-lua-conf.hh rec-lua-conf.cc \
	rec-main.hh rec-main.cc \
	rec-protozero.cc rec-protozero.hh \
	rec-responsestats.hh rec-responsestats.cc \
	rec-rust-lib/cxxsupport.cc \
	rec-snmp.hh rec-snmp.cc \
	rec-system-resolve.hh rec-system-resolve.cc \
	rec-taskqueue.cc rec-taskqueue.hh \
	rec-tcounters.cc rec-tcounters.hh \
	rec-tcp.cc \
	rec-tcpout.cc rec-tcpout.hh \
	rec-xfr.cc rec-xfr.hh \
	rec-xfrtracker.cc \
	rec-zonetocache.cc rec-zonetocache.hh \
	rec_channel.cc rec_channel.hh rec_metrics.hh \
	rec_channel_rec.cc \
	recpacketcache.cc recpacketcache.hh \
	recursor_cache.cc recursor_cache.hh \
	reczones-helpers.cc reczones-helpers.hh \
	reczones.cc \
	remote_logger.cc remote_logger.hh \
	resolve-context.hh \
	resolver.hh resolver.cc \
	root-addresses.hh \
	root-dnssec.hh \
	rpzloader.cc rpzloader.hh \
	secpoll-recursor.cc secpoll-recursor.hh \
	secpoll.cc secpoll.hh \
	sha.hh \
	sholder.hh \
	shuffle.cc shuffle.hh \
	sillyrecords.cc \
	snmp-agent.hh snmp-agent.cc \
	sortlist.cc sortlist.hh \
	sstuff.hh \
	stable-bloom.hh \
	stat_t.hh \
	svc-records.cc svc-records.hh \
	syncres.cc syncres.hh \
	taskqueue.cc taskqueue.hh \
	tcounters.hh \
	tcpiohandler.cc tcpiohandler.hh \
	threadname.hh threadname.cc \
	tsigverifier.cc tsigverifier.hh \
	ueberbackend.hh \
	unix_utility.cc \
	utility.hh \
	uuid-utils.hh uuid-utils.cc \
	validate.cc validate.hh validate-recursor.cc validate-recursor.hh \
	version.cc version.hh \
	views.hh \
	webserver.cc webserver.hh \
	ws-api.cc ws-api.hh \
	ws-recursor.cc ws-recursor.hh \
	zonemd.cc zonemd.hh \
	zoneparser-tng.cc zoneparser-tng.hh

nodist_pdns_recursor_SOURCES = \
	rec-rust-lib/cxxsettings-generated.cc

if !HAVE_LUA_HPP
BUILT_SOURCES += lua.hpp
nodist_pdns_recursor_SOURCES += lua.hpp
endif

CLEANFILES += lua.hpp

pdns_recursor_LDADD = \
	$(JSON11_LIBS) \
	$(LIBCRYPTO_LIBS) \
	$(BOOST_CONTEXT_LIBS) \
	$(NET_SNMP_LIBS) \
	$(SYSTEMD_LIBS) \
	$(RT_LIBS) \
	$(BOOST_SYSTEM_LIBS) \
	$(PROBDS_LIBS) \
	$(LIBCAP_LIBS) \
	$(ARC4RANDOM_LIBS) \
	$(RUST_LIBS)

pdns_recursor_LDFLAGS = $(AM_LDFLAGS) \
	$(LIBCRYPTO_LDFLAGS) $(BOOST_CONTEXT_LDFLAGS) \
	$(BOOST_SYSTEM_LDFLAGS)

if NOD_ENABLED
pdns_recursor_SOURCES += nod.hh nod.cc
pdns_recursor_LDADD += \
	$(BOOST_FILESYSTEM_LIBS)
pdns_recursor_LDFLAGS += \
	$(BOOST_FILESYSTEM_LDFLAGS)
endif

rec_control_LDADD = $(LIBCRYPTO_LIBS) $(ARC4RANDOM_LIBS) $(RUST_LIBS)

rec_control_LDFLAGS = $(AM_LDFLAGS) \
	$(LIBCRYPTO_LDFLAGS)

testrunner_SOURCES = \
	aggressive_nsec.cc aggressive_nsec.hh \
	arguments.cc \
	axfr-retriever.hh axfr-retriever.cc \
	base32.cc \
	base64.cc base64.hh \
	circular_buffer.hh \
	credentials.cc credentials.hh \
	dns.cc dns.hh \
	dns_random.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.hh dnsparser.cc \
	dnsrecords.cc \
	dnssecinfra.cc \
	dnsseckeeper.hh \
	dnswriter.cc dnswriter.hh \
	ednscookies.cc ednscookies.hh \
	ednsextendederror.cc ednsextendederror.hh \
	ednsoptions.cc ednsoptions.hh \
	ednspadding.cc ednspadding.hh \
	ednssubnet.cc ednssubnet.hh \
	filterpo.cc filterpo.hh \
	gettime.cc gettime.hh \
	gss_context.cc gss_context.hh \
	iputils.cc iputils.hh \
	ixfr.cc ixfr.hh \
	logger.cc logger.hh \
	logging.hh logging.cc logr.hh \
	misc.cc misc.hh \
	mtasker_context.cc \
	namespaces.hh \
	negcache.hh negcache.cc \
	nsecrecords.cc \
	opensslsigners.cc opensslsigners.hh \
	pdnsexception.hh \
	pollmplexer.cc \
	qtype.cc qtype.hh \
	query-local-address.hh query-local-address.cc \
	ratelimitedlog.hh \
	rcpgenerator.cc \
	rec-eventtrace.cc rec-eventtrace.hh \
	rec-responsestats.hh rec-responsestats.cc \
	rec-rust-lib/cxxsupport.cc \
	rec-system-resolve.hh rec-system-resolve.cc \
	rec-taskqueue.cc rec-taskqueue.hh \
	rec-tcounters.cc rec-tcounters.hh \
	rec-web-stubs.hh \
	rec-xfrtracker.cc \
	rec-zonetocache.cc rec-zonetocache.hh \
	recpacketcache.cc recpacketcache.hh \
	recursor_cache.cc recursor_cache.hh \
	reczones-helpers.cc reczones-helpers.hh \
	resolver.hh resolver.cc \
	root-dnssec.hh \
	rpzloader.cc rpzloader.hh \
	secpoll.cc \
	sholder.hh \
	shuffle.cc shuffle.hh \
	sillyrecords.cc \
	sortlist.cc sortlist.hh \
	sstuff.hh \
	stable-bloom.hh \
	svc-records.cc svc-records.hh \
	syncres.cc syncres.hh \
	taskqueue.cc taskqueue.hh \
	test-aggressive_nsec_cc.cc \
	test-arguments_cc.cc \
	test-base32_cc.cc \
	test-base64_cc.cc \
	test-common.hh \
	test-credentials_cc.cc \
	test-dns_random_hh.cc \
	test-dnsname_cc.cc \
	test-dnsparser_hh.cc \
	test-dnsrecordcontent.cc \
	test-dnsrecords_cc.cc \
	test-ednscookie_cc.cc \
	test-ednsoptions_cc.cc \
	test-filterpo_cc.cc \
	test-histogram_hh.cc \
	test-iputils_hh.cc \
	test-ixfr_cc.cc \
	test-luawrapper.cc \
	test-misc_hh.cc \
	test-mplexer.cc \
	test-mtasker.cc \
	test-negcache_cc.cc \
	test-packetcache_hh.cc \
	test-rcpgenerator_cc.cc \
	test-rec-system-resolve.cc \
	test-rec-taskqueue.cc \
	test-rec-tcounters_cc.cc \
	test-rec-zonetocache.cc \
	test-recpacketcache_cc.cc \
	test-recursorcache_cc.cc \
	test-reczones-helpers.cc \
	test-rpzloader_cc.cc \
	test-secpoll_cc.cc \
	test-settings.cc \
	test-sholder_hh.cc \
	test-shuffle_cc.cc \
	test-signers.cc \
	test-syncres_cc.cc \
	test-syncres_cc.hh \
	test-syncres_cc1.cc \
	test-syncres_cc10.cc \
	test-syncres_cc2.cc \
	test-syncres_cc3.cc \
	test-syncres_cc4.cc \
	test-syncres_cc5.cc \
	test-syncres_cc6.cc \
	test-syncres_cc7.cc \
	test-syncres_cc8.cc \
	test-syncres_cc9.cc \
	test-tsig.cc \
	testrunner.cc \
	threadname.hh threadname.cc \
	tsigverifier.cc tsigverifier.hh \
	unix_utility.cc \
	validate-recursor.cc validate-recursor.hh \
	validate.cc validate.hh \
	version.cc version.hh \
	zonemd.cc zonemd.hh \
	zoneparser-tng.cc zoneparser-tng.hh

nodist_testrunner_SOURCES = \
	rec-rust-lib/cxxsettings-generated.cc

testrunner_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(BOOST_CONTEXT_LDFLAGS) \
	$(BOOST_UNIT_TEST_FRAMEWORK_LDFLAGS) \
	$(LIBCRYPTO_LDFLAGS) \
	$(BOOST_SYSTEM_LDFLAGS)

testrunner_LDADD = \
	$(BOOST_CONTEXT_LIBS) \
	$(BOOST_UNIT_TEST_FRAMEWORK_LIBS) \
	$(LIBCRYPTO_LIBS) \
	$(RT_LIBS) \
	$(BOOST_SYSTEM_LIBS) \
	$(PROBDS_LIBS) \
	$(LIBCAP_LIBS) \
	$(ARC4RANDOM_LIBS) \
	$(RUST_LIBS)

if NOD_ENABLED
testrunner_SOURCES +=   nod.hh nod.cc \
			test-nod_cc.cc

testrunner_LDADD += \
	$(BOOST_FILESYSTEM_LIBS)
testrunner_LDFLAGS += \
	$(BOOST_FILESYSTEM_LDFLAGS)
endif

if LIBSODIUM
pdns_recursor_SOURCES += \
	sodiumsigners.cc
pdns_recursor_LDADD += $(LIBSODIUM_LIBS)

rec_control_LDADD += $(LIBSODIUM_LIBS)

testrunner_SOURCES += \
	sodiumsigners.cc
testrunner_LDADD += $(LIBSODIUM_LIBS)
endif



if MALLOC_TRACE
pdns_recursor_SOURCES += \
	malloctrace.cc \
	malloctrace.hh
pdns_recursor_LDFLAGS += -rdynamic
endif

if LUA
pdns_recursor_LDADD += $(LUA_LIBS)
rec_control_LDADD += $(LUA_LIBS)
testrunner_LDADD += $(LUA_LIBS)
endif

if HAVE_FREEBSD
pdns_recursor_SOURCES += kqueuemplexer.cc
testrunner_SOURCES += kqueuemplexer.cc
endif

if HAVE_OPENBSD
pdns_recursor_SOURCES += kqueuemplexer.cc
testrunner_SOURCES += kqueuemplexer.cc
endif

if HAVE_DARWIN
pdns_recursor_SOURCES += kqueuemplexer.cc
testrunner_SOURCES += kqueuemplexer.cc
endif

if HAVE_LINUX
pdns_recursor_SOURCES += epollmplexer.cc
testrunner_SOURCES += epollmplexer.cc
endif

if HAVE_SOLARIS
pdns_recursor_SOURCES += \
	devpollmplexer.cc \
	portsmplexer.cc
testrunner_SOURCES += \
	devpollmplexer.cc \
	portsmplexer.cc
endif

if FSTRM
pdns_recursor_SOURCES += \
	dnstap.cc dnstap.hh

pdns_recursor_LDADD += \
	$(FSTRM_LIBS)
endif

if HAVE_DNS_OVER_TLS
if HAVE_LIBSSL
AM_CPPFLAGS += $(LIBSSL_CFLAGS)
pdns_recursor_LDADD += $(LIBSSL_LIBS)
endif

#if HAVE_GNUTLS
#AM_CPPFLAGS += $(GNUTLS_CFLAGS)
#pdns_recursor_LDADD += $(GNUTLS_LIBS)
#endif
endif
if HAVE_LIBCURL
pdns_recursor_SOURCES += minicurl.cc minicurl.hh
pdns_recursor_LDADD += $(LIBCURL)
testrunner_SOURCES += minicurl.cc minicurl.hh
testrunner_LDADD += $(LIBCURL)
endif


rec_control_SOURCES = \
	arguments.cc arguments.hh \
	base32.cc base32.hh \
	base64.cc base64.hh \
	credentials.cc credentials.hh \
	dnslabeltext.cc \
	dnsname.hh dnsname.cc \
	dnsparser.cc dnsparser.hh \
	dnsrecords.cc dnsrecords.hh \
	dnswriter.cc dnswriter.hh \
	filterpo.cc filterpo.hh \
	iputils.cc iputils.hh \
	logger.cc \
	logging.cc \
	lua-base4.cc lua-base4.hh \
	misc.cc \
	nsecrecords.cc \
	qtype.cc \
	rcpgenerator.cc	rcpgenerator.hh \
	rec-lua-conf.cc rec-lua-conf.hh \
	rec-rust-lib/cxxsupport.cc \
	rec-system-resolve.cc rec-system-resolve.hh \
	rec-web-stubs.hh \
	rec_channel.cc rec_channel.hh \
	rec_control.cc \
	sillyrecords.cc \
	sortlist.cc sortlist.hh \
	svc-records.cc svc-records.hh \
	threadname.cc threadname.hh \
	unix_utility.cc

nodist_rec_control_SOURCES = \
	rec-rust-lib/cxxsettings-generated.cc

dnslabeltext.cc: dnslabeltext.rl
	$(AM_V_GEN)$(RAGEL) $< -o dnslabeltext.cc

curl_verbose = $(curl_verbose_$(V))
curl_verbose_ = $(curl_verbose_$(AM_DEFAULT_VERBOSITY))
curl_verbose_0 = @echo "  CURL    " $@;
$(srcdir)/effective_tld_names.dat:
	$(curl_verbose)if ! curl -s -S https://publicsuffix.org/list/public_suffix_list.dat > $@; then rm -f $@; exit 1; fi

pubsuffix.cc: $(srcdir)/effective_tld_names.dat
	$(srcdir)/mkpubsuffixcc $< $@

## Config file
sysconf_DATA = recursor.yml-dist

recursor.yml-dist: pdns_recursor
	./pdns_recursor --config=default 2> /dev/null > $@

## Manpages
MANPAGES=pdns_recursor.1 \
	 rec_control.1

dist_man_MANS=$(MANPAGES)

if HAVE_VENV
if !HAVE_MANPAGES
$(MANPAGES): %: docs/manpages/%.rst .venv
	$(builddir)/.venv/bin/python -msphinx -b man "$(srcdir)/docs" "$(builddir)" $<
endif # if !HAVE_MANPAGES

.venv: docs/requirements.txt
	$(PYTHON) -m venv .venv
	.venv/bin/pip install -U pip setuptools
	.venv/bin/pip install -r ${top_srcdir}/docs/requirements.txt

html-docs: docs/** .venv
	.venv/bin/python -msphinx -b html docs html-docs

latex/PowerDNS-Recursor.pdf: docs/** .venv
	.venv/bin/python -msphinx -M latexpdf docs .

PowerDNS-Recursor.pdf: latex/PowerDNS-Recursor.pdf
	mv $< $@

html-docs.tar.bz2: html-docs
	tar cjf $@ $<

all-docs: PowerDNS-Recursor.pdf html-docs html-docs.tar.bz2

upload-docs: all-docs
	rsync -crv --delete --no-p --chmod=g=rwX --exclude '*~' ./html-docs/ web1.powerdns.com:/srv/www/doc.powerdns.com/recursor/
	rsync -crv --no-p --chmod=g=rwX --exclude '*~' ./html-docs.tar.bz2 web1.powerdns.com:/srv/www/doc.powerdns.com/recursor/
	rsync -crv --no-p --chmod=g=rwX --exclude '*~' ./PowerDNS-Recursor.pdf web1.powerdns.com:/srv/www/doc.powerdns.com/recursor/

else # if HAVE_VENV
$(MANPAGES):
	@echo "You need Python 3 and the 'venv' module to generate the manpages"
	exit 1

PowerDNS-Recursor.pdf:
	@echo "You need Python 3 and the 'venv' module to generate the PDF"
	exit 1

html-docs:
	@echo "You need Python 3 and the 'venv' module to generate the HTML docs"
	exit 1
endif

if HAVE_SYSTEMD
pdns-recursor.service: pdns-recursor.service.in
	$(AM_V_GEN)sed -e 's![@]bindir[@]!$(bindir)!' -e 's![@]sbindir[@]!$(sbindir)!' -e 's![@]service_user[@]!$(service_user)!' -e 's![@]service_group[@]!$(service_group)!' < $< > $@
if !HAVE_SYSTEMD_WITH_RUNTIME_DIR_ENV
if HAVE_SYSTEMD_PERCENT_T
	$(AM_V_GEN)sed -e 's!/pdns_recursor!& --socket-dir=%t/pdns-recursor!' -i $@
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

pdns-recursor@.service: pdns-recursor.service
	$(AM_V_GEN)sed -e 's!/pdns_recursor!& --config-name=%i!' \
	  -e 's!Recursor!& %i!' \
	  -e 's!SyslogIdentifier=.*!&-%i!' \
	  < $< > $@
if HAVE_SYSTEMD_PERCENT_T
	$(AM_V_GEN)sed -e 's!RuntimeDirectory=.*!&-%i!' \
	  -e 's!--socket-dir=%t/pdns-recursor!--config-name=%i --socket-dir=%t/pdns-recursor-%i!' -i $@
if !HAVE_SYSTEMD_WITH_RUNTIME_DIR_ENV
	$(AM_V_GEN)sed -e 's!--socket-dir=[^ ]\+!&-%i !' -i $@
endif
endif

systemdsystemunitdir = $(SYSTEMD_DIR)

systemdsystemunit_DATA = \
	pdns-recursor.service \
	pdns-recursor@.service

CLEANFILES += \
	pdns-recursor.service \
	pdns-recursor@.service

endif

if !HAVE_LUA_HPP
include lua_hpp.mk
endif
