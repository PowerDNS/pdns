JSON11_LIBS = $(top_srcdir)/ext/json11/libjson11.la
PROBDS_LIBS = $(top_srcdir)/ext/probds/libprobds.la

AM_CPPFLAGS = $(LUA_CFLAGS) $(YAHTTP_CFLAGS) $(BOOST_CPPFLAGS) $(LIBSODIUM_CFLAGS) $(NET_SNMP_CFLAGS) $(LIBCAP_CFLAGS) $(SANITIZER_FLAGS) -O3 -Wall -pthread -DSYSCONFDIR=\"${sysconfdir}\" $(SYSTEMD_CFLAGS)

AM_CPPFLAGS += \
	-I$(top_srcdir)/ext/json11 \
	$(YAHTTP_CFLAGS) \
	$(LIBCRYPTO_INCLUDES)

AM_CXXFLAGS = \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DPKGLIBDIR=\"$(pkglibdir)\" \
	-DLOCALSTATEDIR=\"$(socketdir)\"

if NOD_ENABLED
AM_CXXFLAGS += \
	-DNODCACHEDIR=\"$(nodcachedir)\"
endif

if FSTRM
AM_CPPFLAGS += \
	$(FSTRM_CFLAGS)
endif

AM_LDFLAGS = \
	$(PROGRAM_LDFLAGS) \
	$(THREADFLAGS)

ACLOCAL_AMFLAGS = -I m4

BUILT_SOURCES=htmlfiles.h \
	dnslabeltext.cc

CLEANFILES = htmlfiles.h \
	dnsmessage.pb.cc \
	dnsmessage.pb.h \
	recursor.conf-dist

htmlfiles.h: html/*
	./incfiles > $@

SUBDIRS=ext

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
	mtasker.cc \
	mtasker_fcontext.cc mtasker_ucontext.cc \
	NOTICE \
	opensslsigners.hh opensslsigners.cc \
	portsmplexer.cc \
	dnstap.proto dnstap.cc dnstap.hh fstrm_logger.cc fstrm_logger.hh rec-dnstap.hh \
	rrd/* \
	html incfiles \
	test_libcrypto \
	pdns-recursor.service.in \
	RECURSOR-MIB.txt \
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
TESTS_ENVIRONMENT = env BOOST_TEST_LOG_LEVEL=message SRCDIR='$(srcdir)'
TESTS += testrunner
else
check-local:
	@echo "Unit tests are not enabled"
	@echo "Run ./configure --enable-unit-tests"
endif

pdns_recursor_SOURCES = \
	arguments.cc \
	ascii.hh \
	base32.cc base32.hh \
	base64.cc base64.hh \
	cachecleaner.hh \
	capabilities.cc capabilities.hh \
	circular_buffer.hh \
	comment.hh \
	dns.hh dns.cc \
	dns_random.hh dns_random.cc \
	dnsbackend.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnspacket.hh \
	dnsparser.hh dnsparser.cc \
	dnsrecords.cc dnsrecords.hh \
	dnssecinfra.hh dnssecinfra.cc \
	dnsseckeeper.hh \
	dnswriter.cc dnswriter.hh \
	ednsoptions.cc ednsoptions.hh \
	ednssubnet.cc ednssubnet.hh \
	filterpo.cc filterpo.hh \
	fstrm_logger.cc fstrm_logger.hh \
	gettime.cc gettime.hh \
	gss_context.cc gss_context.hh \
	iputils.hh iputils.cc \
	ixfr.cc ixfr.hh \
	json.cc json.hh \
	lazy_allocator.hh \
	lock.hh \
	logger.hh logger.cc \
	lua-base4.cc lua-base4.hh \
	lua-recursor4.cc lua-recursor4.hh \
	lua-recursor4-ffi.hh \
	lwres.cc lwres.hh \
	misc.hh misc.cc \
	mplexer.hh \
	mtasker.hh \
	mtasker_context.cc mtasker_context.hh \
	namespaces.hh \
	negcache.hh negcache.cc \
	nsecrecords.cc \
	opensslsigners.cc opensslsigners.hh \
	packetcache.hh \
	pdns_recursor.cc \
	pdnsexception.hh \
	pollmplexer.cc \
	protobuf.cc protobuf.hh \
	pubsuffix.hh pubsuffix.cc \
	pubsuffixloader.cc \
	qtype.hh qtype.cc \
	rcpgenerator.cc rcpgenerator.hh \
	rec-carbon.cc \
	rec-lua-conf.hh rec-lua-conf.cc \
	rec-protobuf.cc rec-protobuf.hh \
	rec-snmp.hh rec-snmp.cc \
	rec_channel.cc rec_channel.hh rec_metrics.hh \
	rec_channel_rec.cc \
	recpacketcache.cc recpacketcache.hh \
	recursor_cache.cc recursor_cache.hh \
	reczones.cc \
	remote_logger.cc remote_logger.hh \
	resolver.hh resolver.cc \
	resolve-context.hh \
	responsestats.hh responsestats.cc \
	root-addresses.hh \
	root-dnssec.hh \
	rpzloader.cc rpzloader.hh \
	secpoll-recursor.cc secpoll-recursor.hh \
	secpoll.cc secpoll.hh \
	sholder.hh \
	sillyrecords.cc \
	snmp-agent.hh snmp-agent.cc \
	sortlist.cc sortlist.hh \
	sstuff.hh \
	stable-bloom.hh \
	syncres.cc syncres.hh \
	threadname.hh threadname.cc \
	tsigverifier.cc tsigverifier.hh \
	ueberbackend.hh \
	unix_utility.cc \
	utility.hh \
	uuid-utils.hh uuid-utils.cc \
	validate.cc validate.hh validate-recursor.cc validate-recursor.hh \
	version.cc version.hh \
	webserver.cc webserver.hh \
	ws-api.cc ws-api.hh \
	ws-recursor.cc ws-recursor.hh \
	xpf.cc xpf.hh \
	zoneparser-tng.cc zoneparser-tng.hh

if !HAVE_LUA_HPP
BUILT_SOURCES += lua.hpp
nodist_pdns_recursor_SOURCES = lua.hpp
CLEANFILES += lua.hpp
endif

pdns_recursor_LDADD = \
	$(YAHTTP_LIBS) \
	$(JSON11_LIBS) \
	$(LIBCRYPTO_LIBS) \
	$(BOOST_CONTEXT_LIBS) \
	$(NET_SNMP_LIBS) \
	$(SYSTEMD_LIBS) \
	$(RT_LIBS) \
	$(BOOST_SYSTEM_LIBS) \
	$(PROBDS_LIBS) \
	$(LIBCAP_LIBS)

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

testrunner_SOURCES = \
	arguments.cc \
	base32.cc \
	base64.cc base64.hh \
	circular_buffer.hh \
	dns.cc dns.hh \
	dns_random.cc dns_random.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.hh dnsparser.cc \
	dnsrecords.cc \
	dnssecinfra.cc \
	dnsseckeeper.hh \
	dnswriter.cc dnswriter.hh \
	ednscookies.cc ednscookies.hh \
	ednsoptions.cc ednsoptions.hh \
	ednssubnet.cc ednssubnet.hh \
	filterpo.cc filterpo.hh \
	gettime.cc gettime.hh \
	gss_context.cc gss_context.hh \
	iputils.cc iputils.hh \
	ixfr.cc ixfr.hh \
	logger.cc logger.hh \
	misc.cc misc.hh \
	mtasker_context.cc \
	negcache.hh negcache.cc \
	namespaces.hh \
	nsecrecords.cc \
	pdnsexception.hh \
	opensslsigners.cc opensslsigners.hh \
	pollmplexer.cc \
	protobuf.cc protobuf.hh \
	qtype.cc qtype.hh \
	rcpgenerator.cc \
	rec-protobuf.cc rec-protobuf.hh \
	recpacketcache.cc recpacketcache.hh \
	recursor_cache.cc recursor_cache.hh \
	responsestats.cc \
	rpzloader.cc rpzloader.hh \
	resolver.hh resolver.cc \
	root-dnssec.hh \
	secpoll.cc \
	sillyrecords.cc \
	sholder.hh \
	sstuff.hh \
	stable-bloom.hh \
	syncres.cc syncres.hh \
	test-arguments_cc.cc \
	test-base32_cc.cc \
	test-base64_cc.cc \
	test-common.hh \
	test-dnsrecordcontent.cc \
	test-dns_random_hh.cc \
	test-dnsname_cc.cc \
	test-dnsparser_hh.cc \
	test-dnsrecords_cc.cc \
	test-ednsoptions_cc.cc \
	test-filterpo_cc.cc \
	test-iputils_hh.cc \
	test-ixfr_cc.cc \
	test-misc_hh.cc \
	test-mtasker.cc \
	test-mplexer.cc \
	test-negcache_cc.cc \
	test-packetcache_hh.cc \
	test-rcpgenerator_cc.cc \
	test-recpacketcache_cc.cc \
	test-recursorcache_cc.cc \
	test-rpzloader_cc.cc \
	test-secpoll_cc.cc \
	test-signers.cc \
	test-syncres_cc.hh \
	test-syncres_cc.cc \
	test-syncres_cc1.cc \
	test-syncres_cc2.cc \
	test-syncres_cc3.cc \
	test-syncres_cc4.cc \
	test-syncres_cc5.cc \
	test-syncres_cc6.cc \
	test-syncres_cc7.cc \
	test-syncres_cc8.cc \
	test-syncres_cc9.cc \
	test-tsig.cc \
	test-xpf_cc.cc \
	testrunner.cc \
	threadname.hh threadname.cc \
	tsigverifier.cc tsigverifier.hh \
	unix_utility.cc \
	validate.cc validate.hh \
	validate-recursor.cc validate-recursor.hh \
	xpf.cc xpf.hh \
	zoneparser-tng.cc zoneparser-tng.hh

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
	$(LIBCAP_LIBS)

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
testrunner_SOURCES += \
	sodiumsigners.cc
testrunner_LDADD += $(LIBSODIUM_LIBS)
endif

if LIBDECAF
pdns_recursor_SOURCES += \
	decafsigners.cc
pdns_recursor_LDADD += $(LIBDECAF_LIBS)
endif

if MALLOC_TRACE
pdns_recursor_SOURCES += \
	malloctrace.cc \
	malloctrace.hh
pdns_recursor_LDFLAGS += -rdynamic
endif

if LUA
pdns_recursor_LDADD += $(LUA_LIBS)
endif

if HAVE_FREEBSD
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

if HAVE_PROTOBUF
if HAVE_PROTOC
dnsmessage.pb.cc: dnsmessage.proto
	$(AM_V_GEN)$(PROTOC) --cpp_out=./ $<

if FSTRM
dnstap.pb.cc: dnstap.proto
	$(AM_V_GEN)$(PROTOC) -I$(srcdir) --cpp_out=./ $<
endif


BUILT_SOURCES += dnsmessage.pb.cc
pdns_recursor_LDADD += $(PROTOBUF_LIBS)
nodist_pdns_recursor_SOURCES = dnsmessage.pb.cc dnsmessage.pb.h
nodist_testrunner_SOURCES = dnsmessage.pb.cc dnsmessage.pb.h

if FSTRM
BUILT_SOURCES += dnstap.pb.cc
pdns_recursor.$(OBJEXT): dnstap.pb.cc dnsmessage.pb.cc
testrunner$(OBJEXT): dnstap.pb.cc dnsmessage.pb.cc
nodist_pdns_recursor_SOURCES += dnstap.pb.cc dnstap.pb.h
nodist_testrunner_SOURCES += dnstap.pb.cc dnstap.pb.h
else
pdns_recursor.$(OBJEXT): dnsmessage.pb.cc
testrunner$(OBJEXT): dnsmessage.pb.cc
endif

testrunner_LDADD += $(PROTOBUF_LIBS)

endif
endif

if FSTRM
pdns_recursor_SOURCES += \
	dnstap.cc dnstap.hh rec-dnstap.hh

pdns_recursor_LDADD += \
	$(FSTRM_LIBS)
endif

rec_control_SOURCES = \
	arguments.cc arguments.hh \
	dnsname.hh dnsname.cc \
	dnslabeltext.cc \
	logger.cc \
	misc.cc \
	qtype.cc \
	rec_channel.cc rec_channel.hh \
	rec_control.cc \
	unix_utility.cc

dnslabeltext.cc: dnslabeltext.rl
	$(AM_V_GEN)$(RAGEL) $< -o dnslabeltext.cc

curl_verbose = $(curl_verbose_$(V))
curl_verbose_ = $(curl_verbose_$(AM_DEFAULT_VERBOSITY))
curl_verbose_0 = @echo "  CURL    " $@;
$(srcdir)/effective_tld_names.dat:
	$(curl_verbose)if ! curl -s -S https://publicsuffix.org/list/public_suffix_list.dat > $@; then rm -f $@; exit 1; fi

pubsuffix.cc: $(srcdir)/effective_tld_names.dat
	$(AM_V_GEN)./mkpubsuffixcc

## Config file
sysconf_DATA = recursor.conf-dist

recursor.conf-dist: pdns_recursor
	$(AM_V_GEN)./pdns_recursor --config > $@

## Manpages
MANPAGES=pdns_recursor.1 \
	 rec_control.1

dist_man_MANS=$(MANPAGES)

if HAVE_VIRTUALENV
if !HAVE_MANPAGES
$(MANPAGES): %: docs/manpages/%.rst .venv
	.venv/bin/python -msphinx -b man docs . $<
endif # if !HAVE_MANPAGES

.venv: docs/requirements.txt
	virtualenv .venv
	.venv/bin/pip install -U pip setuptools setuptools-git
	.venv/bin/pip install -r docs/requirements.txt

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

else # if HAVE_VIRTUALENV
$(MANPAGES):
	echo "You need virtualenv to generate the manpages"
	exit 1

PowerDNS-Recursor.pdf:
	echo "You need virtualenv to generate the PDF"
	exit 1

html-docs:
	echo "You need virtualenv to generate the HTML docs"
	exit 1
endif

if HAVE_SYSTEMD
pdns-recursor.service: pdns-recursor.service.in
	$(AM_V_GEN)sed -e 's![@]sbindir[@]!$(sbindir)!' -e 's![@]service_user[@]!$(service_user)!' -e 's![@]service_group[@]!$(service_group)!' < $< > $@
if !HAVE_SYSTEMD_LOCK_PERSONALITY
	$(AM_V_GEN)perl -ni -e 'print unless /^LockPersonality/' $@
endif
if !HAVE_SYSTEMD_PRIVATE_DEVICES
	$(AM_V_GEN)perl -ni -e 'print unless /^PrivateDevices/' $@
endif
if !HAVE_SYSTEMD_PRIVATE_TMP
	$(AM_V_GEN)perl -ni -e 'print unless /^PrivateTmp/' $@
endif
if !HAVE_SYSTEMD_PROTECT_CONTROL_GROUPS
	$(AM_V_GEN)perl -ni -e 'print unless /^ProtectControlGroups/' $@
endif
if !HAVE_SYSTEMD_PROTECT_HOME
	$(AM_V_GEN)perl -ni -e 'print unless /^ProtectHome/' $@
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
if !HAVE_SYSTEMD_SYSTEM_CALL_ARCHITECTURES
	$(AM_V_GEN)perl -ni -e 'print unless /^SystemCallArchitectures/' $@
endif
if !HAVE_SYSTEMD_SYSTEM_CALL_FILTER
	$(AM_V_GEN)perl -ni -e 'print unless /^SystemCallFilter/' $@
endif

pdns-recursor@.service: pdns-recursor.service
	$(AM_V_GEN)sed -e 's!/pdns_recursor!& --config-name=%i!' \
	  -e 's!Recursor!& %i!' \
	  < $< > $@

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
