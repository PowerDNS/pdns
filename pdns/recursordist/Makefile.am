JSON11_LIBS = $(top_srcdir)/ext/json11/libjson11.la

AM_CPPFLAGS = $(LUA_CFLAGS) $(YAHTTP_CFLAGS) $(BOOST_CPPFLAGS) $(BOTAN110_CFLAGS) $(SANITIZER_FLAGS) -O3 -Wall -pthread -DSYSCONFDIR=\"${sysconfdir}\" $(SYSTEMD_CFLAGS)

AM_CPPFLAGS += \
	-I$(top_srcdir)/ext/json11 \
	-I$(top_srcdir)/ext/rapidjson/include \
	$(YAHTTP_CFLAGS) \
	$(OPENSSL_INCLUDES)

AM_CXXFLAGS = \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DPKGLIBDIR=\"$(pkglibdir)\" \
	-DLOCALSTATEDIR=\"$(socketdir)\"

AM_LDFLAGS = \
	$(PROGRAM_LDFLAGS) \
	$(THREADFLAGS)

ACLOCAL_AMFLAGS = -I m4

BUILT_SOURCES=htmlfiles.h
CLEANFILES = htmlfiles.h \
	dnsmessage.pb.cc \
	dnsmessage.pb.h

htmlfiles.h: html/*
	./incfiles > $@

SUBDIRS=ext

if LUA
AM_CPPFLAGS +=$(LUA_CFLAGS)
endif

EXTRA_DIST = \
	NOTICE \
	.version \
	botan110signers.cc \
	build-aux/gen-version \
	contrib/* \
	devpollmplexer.cc \
	dnslabeltext.cc \
	dnslabeltext.rl \
	dnsmessage.proto \
	effective_tld_names.dat \
	epollmplexer.cc \
	kqueuemplexer.cc \
	malloctrace.cc malloctrace.hh \
	mtasker.cc \
	mtasker_fcontext.cc mtasker_ucontext.cc \
	opensslsigners.hh opensslsigners.cc \
	pdns_recursor.1.md \
	portsmplexer.cc \
	rec_control.1.md \
	rrd/* \
	html incfiles \
	pdns-recursor.service.in

sbin_PROGRAMS = pdns_recursor
bin_PROGRAMS = rec_control

pdns_recursor_SOURCES = \
	arguments.cc \
	base32.cc base32.hh \
	base64.cc base64.hh \
	cachecleaner.hh \
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
	gettime.cc gettime.hh \
	gss_context.cc gss_context.hh \
	iputils.hh iputils.cc \
	ixfr.cc ixfr.hh \
	json.cc json.hh \
	lazy_allocator.hh \
	lock.hh \
	logger.hh logger.cc \
	lua-recursor4.cc lua-recursor4.hh \
	lwres.cc lwres.hh \
	misc.hh misc.cc \
	mplexer.hh \
	mtasker.hh \
	mtasker_context.cc mtasker_context.hh \
	namespaces.hh \
	nsecrecords.cc \
	opensslsigners.cc opensslsigners.hh \
	pdns_recursor.cc \
	pdnsexception.hh \
	pubsuffix.hh pubsuffix.cc \
	qtype.hh qtype.cc \
	randomhelper.cc \
	rcpgenerator.cc rcpgenerator.hh \
	rec-carbon.cc \
	rec-lua-conf.hh rec-lua-conf.cc \
	rec_channel.cc rec_channel.hh \
	rec_channel_rec.cc \
	recpacketcache.cc recpacketcache.hh \
	recursor_cache.cc recursor_cache.hh \
	reczones.cc \
	remote_logger.cc remote_logger.hh \
	resolver.hh resolver.cc \
	responsestats.hh responsestats.cc \
	root-addresses.hh \
	rpzloader.cc rpzloader.hh \
	secpoll-recursor.cc \
	secpoll-recursor.hh \
	selectmplexer.cc \
	sholder.hh \
	sillyrecords.cc \
	sortlist.cc sortlist.hh \
	sstuff.hh \
	syncres.cc syncres.hh \
	ueberbackend.hh \
	unix_utility.cc \
	utility.hh \
	validate.cc validate.hh validate-recursor.cc validate-recursor.hh \
	version.cc version.hh \
	webserver.cc webserver.hh \
	ws-api.cc ws-api.hh \
	ws-recursor.cc ws-recursor.hh \
	zoneparser-tng.cc zoneparser-tng.hh

pdns_recursor_LDADD = \
	$(YAHTTP_LIBS) \
	$(JSON11_LIBS) \
	$(OPENSSL_LIBS) \
	$(BOOST_CONTEXT_LIBS) \
	$(SYSTEMD_LIBS) \
	$(RT_LIBS)

pdns_recursor_LDFLAGS = $(AM_LDFLAGS) \
	$(OPENSSL_LDFLAGS)

if BOTAN110
pdns_recursor_SOURCES += \
	botan110signers.cc
pdns_recursor_LDADD += $(BOTAN110_LIBS)
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
endif

if HAVE_LINUX
pdns_recursor_SOURCES += epollmplexer.cc
endif

if HAVE_SOLARIS
pdns_recursor_SOURCES += \
	devpollmplexer.cc \
	portsmplexer.cc
endif

if HAVE_PROTOBUF
if HAVE_PROTOC
dnsmessage.pb.cc: dnsmessage.proto
	$(AM_V_GEN)$(PROTOC) --cpp_out=./ $<

BUILT_SOURCES += dnsmessage.pb.cc
pdns_recursor_LDADD += $(PROTOBUF_LIBS)
nodist_pdns_recursor_SOURCES = dnsmessage.pb.cc dnsmessage.pb.h
pdns_recursor.$(OBJEXT): dnsmessage.pb.cc
endif
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

if HAVE_PANDOC
$(MANPAGES): %: %.md
	$(AM_V_GEN)$(PANDOC) -s -t man $< -o $@
else
if HAVE_MANPAGES
#nothing
else
$(MANPAGES):
	echo "You need pandoc to generate the manpages"
	exit 1
endif
endif

if HAVE_SYSTEMD
pdns-recursor.service: pdns-recursor.service.in
	$(AM_V_GEN)sed -e 's![@]sbindir[@]!$(sbindir)!' < $< > $@

systemdsystemunitdir = $(SYSTEMD_DIR)

systemdsystemunit_DATA = \
	pdns-recursor.service
endif
