AM_CPPFLAGS += $(SYSTEMD_CFLAGS) $(LUA_CFLAGS) $(LIBEDIT_CFLAGS) $(YAHTTP_CFLAGS) $(SANITIZER_FLAGS) -DSYSCONFDIR=\"${sysconfdir}\"

ACLOCAL_AMFLAGS = -I m4

SUBDIRS=ext/yahttp

CLEANFILES = dnsmessage.pb.cc dnsmessage.pb.h

dnslabeltext.cc: dnslabeltext.rl
	$(AM_V_GEN)$(RAGEL) $< -o dnslabeltext.cc

BUILT_SOURCES=htmlfiles.h

htmlfiles.h: html/*
	./incfiles > $@

SRC_JS_FILES := $(wildcard src_js/*.js)
MIN_JS_FILES := $(patsubst src_js/%.js,html/js/%.min.js,$(SRC_JS_FILES))

html/js/%.min.js: src_js/%.js
	uglifyjs $< > $@

min_js: $(MIN_JS_FILES)

if HAVE_RE2
AM_CPPFLAGS += $(RE2_CFLAGS)
endif


EXTRA_DIST=dnslabeltext.rl \
	   dnsdistconf.lua \
	   dnsmessage.proto \
	   README.md \
	   delaypipe.cc delaypipe.hh \
	   html \
	   dnsdist.1.md \
	   .version \
	   contrib \
	   build-aux/gen-version \
	   ext/incbin/UNLICENSE \
	   incfiles \
	   src_js \
	   dnsdist.service.in \
	   lua_hpp.mk \
	   bpf-filter.main.ebpf \
	   bpf-filter.qname.ebpf \
	   bpf-filter.ebpf.src

bin_PROGRAMS = dnsdist

if UNIT_TESTS
noinst_PROGRAMS = testrunner
TESTS_ENVIRONMENT = env BOOST_TEST_LOG_LEVEL=message SRCDIR='$(srcdir)'
TESTS=testrunner
else
check-local:
	@echo "Unit tests are not enabled"
	@echo "Run ./configure --enable-unit-tests"
endif

dnsdist-web.$(OBJEXT): htmlfiles.h

dnsdist_SOURCES = \
	base64.hh \
	bpf-filter.cc bpf-filter.hh \
	dns.cc dns.hh \
	dnscrypt.cc dnscrypt.hh \
	dnsdist.cc dnsdist.hh \
	dnsdist-dynbpf.cc dnsdist-dynbpf.hh \
	dnsdist-cache.cc dnsdist-cache.hh \
	dnsdist-carbon.cc \
	dnsdist-console.cc \
	dnsdist-dnscrypt.cc \
	dnsdist-ecs.cc dnsdist-ecs.hh \
	dnsdist-lua.cc \
	dnsdist-lua2.cc \
	dnsdist-protobuf.cc dnsdist-protobuf.hh \
	dnsdist-rings.cc \
	dnsdist-tcp.cc \
	dnsdist-web.cc \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.hh dnsparser.cc \
	dnsrulactions.cc dnsrulactions.hh \
	dnswriter.cc dnswriter.hh \
	dolog.hh \
	ednsoptions.cc ednsoptions.hh \
	ednscookies.cc ednscookies.hh \
	ednssubnet.cc ednssubnet.hh \
	gettime.cc gettime.hh \
	iputils.cc iputils.hh \
	lock.hh \
	misc.cc misc.hh \
	htmlfiles.h \
	namespaces.hh \
	pdnsexception.hh \
	qtype.cc qtype.hh \
	remote_logger.cc remote_logger.hh \
	sholder.hh \
	sodcrypto.cc sodcrypto.hh \
	sstuff.hh \
	statnode.cc statnode.hh \
	ext/luawrapper/include/LuaContext.hpp \
	ext/json11/json11.cpp \
	ext/json11/json11.hpp \
	ext/incbin/incbin.h \
	ext/libbpf/libbpf.h

dnsdist_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(PROGRAM_LDFLAGS) \
	-pthread 

dnsdist_LDADD = \
	$(LUA_LIBS) \
	$(LIBEDIT_LIBS) \
	$(RT_LIBS) \
	$(YAHTTP_LIBS) \
	$(LIBSODIUM_LIBS) \
	$(SANITIZER_FLAGS) \
	$(SYSTEMD_LIBS)

if HAVE_RE2
dnsdist_LDADD += $(RE2_LIBS)
endif

if !HAVE_LUA_HPP
BUILT_SOURCES += lua.hpp
nodist_dnsdist_SOURCES = lua.hpp
CLEANFILES += lua.hpp
endif

if HAVE_PROTOBUF
if HAVE_PROTOC
dnsmessage.pb.cc: dnsmessage.proto
	$(AM_V_GEN)$(PROTOC) --cpp_out=./ $<

BUILT_SOURCES += dnsmessage.pb.cc

nodist_dnsdist_SOURCES = dnsmessage.pb.cc dnsmessage.pb.h
dnsdist_LDADD += $(PROTOBUF_LIBS)

dnsdist.$(OBJEXT): dnsmessage.pb.cc
endif
endif

testrunner_SOURCES = \
	base64.hh \
	dns.hh \
	test-base64_cc.cc \
	test-dnsdist_cc.cc \
	test-dnsdistpacketcache_cc.cc \
	test-dnscrypt_cc.cc \
	dnsdist.hh \
	dnsdist-cache.cc dnsdist-cache.hh \
	dnsdist-ecs.cc dnsdist-ecs.hh \
	dnscrypt.cc dnscrypt.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.hh dnsparser.cc \
	dnswriter.cc dnswriter.hh \
	dolog.hh \
	ednsoptions.cc ednsoptions.hh \
	ednscookies.cc ednscookies.hh \
	ednssubnet.cc ednssubnet.hh \
	gettime.cc gettime.hh \
	iputils.cc iputils.hh \
	misc.cc misc.hh \
	namespaces.hh \
	pdnsexception.hh \
	qtype.cc qtype.hh \
	sholder.hh \
	sodcrypto.cc \
	sstuff.hh \
	testrunner.cc

testrunner_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(PROGRAM_LDFLAGS) \
	$(BOOST_UNIT_TEST_FRAMEWORK_LDFLAGS) \
	-pthread

testrunner_LDADD = \
	$(BOOST_UNIT_TEST_FRAMEWORK_LIBS) \
	$(LIBSODIUM_LIBS) \
	$(RT_LIBS) \
	$(SANITIZER_FLAGS)

MANPAGES=dnsdist.1

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
dnsdist.service: dnsdist.service.in
	$(AM_V_GEN)sed -e 's![@]bindir[@]!$(bindir)!' < $< > $@

systemdsystemunitdir = $(SYSTEMD_DIR)

systemdsystemunit_DATA = \
	dnsdist.service
endif

if !HAVE_LUA_HPP
include lua_hpp.mk
endif
