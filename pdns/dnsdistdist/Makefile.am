AM_CPPFLAGS += $(SYSTEMD_CFLAGS) $(LUA_CFLAGS) $(LIBEDIT_CFLAGS) $(LIBSODIUM_CFLAGS) $(FSTRM_CFLAGS) $(YAHTTP_CFLAGS) $(SANITIZER_FLAGS) $(NET_SNMP_CFLAGS) $(LIBCAP_CFLAGS) -DSYSCONFDIR=\"${sysconfdir}\"

ACLOCAL_AMFLAGS = -I m4

SUBDIRS=ext/ipcrypt \
	ext/yahttp

CLEANFILES = \
	dnsmessage.pb.cc \
	dnsmessage.pb.h \
	htmlfiles.h.tmp \
	htmlfiles.h \
	dnstap.pb.cc \
	dnstap.pb.h

dnslabeltext.cc: dnslabeltext.rl
	$(AM_V_GEN)$(RAGEL) $< -o dnslabeltext.cc

BUILT_SOURCES=htmlfiles.h \
	dnslabeltext.cc

htmlfiles.h: $(srcdir)/html/*
	$(AM_V_GEN)$(srcdir)/incfiles $(srcdir) > $@.tmp
	@mv $@.tmp $@

SRC_JS_FILES := $(wildcard src_js/*.js)
MIN_JS_FILES := $(patsubst src_js/%.js,html/js/%.min.js,$(SRC_JS_FILES))

html/js/%.min.js: src_js/%.js
	uglifyjs $< > $@

min_js: $(MIN_JS_FILES)

if HAVE_RE2
AM_CPPFLAGS += $(RE2_CFLAGS)
endif

if HAVE_DNS_OVER_TLS
if HAVE_LIBSSL
AM_CPPFLAGS += $(LIBSSL_CFLAGS)
endif

if HAVE_GNUTLS
AM_CPPFLAGS += $(GNUTLS_CFLAGS)
endif
endif

if HAVE_LIBCRYPTO
AM_CPPFLAGS += $(LIBCRYPTO_INCLUDES)
endif

if HAVE_CDB
AM_CPPFLAGS += $(CDB_CFLAGS)
endif

if HAVE_LMDB
AM_CPPFLAGS += $(LMDB_CFLAGS)
endif

if HAVE_DNS_OVER_HTTPS
if HAVE_LIBSSL
AM_CPPFLAGS += $(LIBSSL_CFLAGS)
endif

if HAVE_LIBH2OEVLOOP
AM_CPPFLAGS += $(LIBH2OEVLOOP_CFLAGS)
endif
endif

EXTRA_DIST=COPYING \
	   dnslabeltext.rl \
	   dnsdistconf.lua \
	   dnsmessage.proto \
	   dnstap.proto \
	   README.md \
	   delaypipe.cc delaypipe.hh \
	   html \
	   contrib \
	   ext/incbin/UNLICENSE \
	   incfiles \
	   src_js \
	   dnsdist.service.in \
	   lua_hpp.mk \
	   bpf-filter.main.ebpf \
	   bpf-filter.qname.ebpf \
	   bpf-filter.ebpf.src \
	   DNSDIST-MIB.txt \
	   devpollmplexer.cc \
	   epollmplexer.cc \
	   kqueuemplexer.cc \
	   portsmplexer.cc \
	   cdb.cc cdb.hh \
	   ext/lmdb-safe/lmdb-safe.cc ext/lmdb-safe/lmdb-safe.hh \
	   builder-support/gen-version

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
	ascii.hh \
	base64.hh \
	bpf-filter.cc bpf-filter.hh \
	cachecleaner.hh \
	capabilities.cc capabilities.hh \
	circular_buffer.hh \
	dns.cc dns.hh \
	dnscrypt.cc dnscrypt.hh \
	dnsdist.cc dnsdist.hh \
	dnsdist-dynbpf.cc dnsdist-dynbpf.hh \
	dnsdist-cache.cc dnsdist-cache.hh \
	dnsdist-carbon.cc \
	dnsdist-console.cc dnsdist-console.hh \
	dnsdist-dnscrypt.cc \
	dnsdist-dynblocks.hh \
	dnsdist-ecs.cc dnsdist-ecs.hh \
	dnsdist-idstate.cc \
	dnsdist-kvs.hh dnsdist-kvs.cc \
	dnsdist-lua.hh dnsdist-lua.cc \
	dnsdist-lua-actions.cc \
	dnsdist-lua-bindings.cc \
	dnsdist-lua-bindings-dnscrypt.cc \
	dnsdist-lua-bindings-dnsquestion.cc \
	dnsdist-lua-bindings-kvs.cc \
	dnsdist-lua-bindings-packetcache.cc \
	dnsdist-lua-bindings-protobuf.cc \
	dnsdist-lua-inspection.cc \
	dnsdist-lua-inspection-ffi.cc dnsdist-lua-inspection-ffi.hh \
	dnsdist-lua-rules.cc \
	dnsdist-lua-vars.cc \
	dnsdist-protobuf.cc dnsdist-protobuf.hh \
	dnsdist-rings.cc dnsdist-rings.hh \
	dnsdist-rules.hh \
	dnsdist-secpoll.cc dnsdist-secpoll.hh \
	dnsdist-snmp.cc dnsdist-snmp.hh \
	dnsdist-tcp.cc \
	dnsdist-web.cc \
	dnsdist-xpf.cc dnsdist-xpf.hh \
	dnslabeltext.cc \
	dnsname.cc dnsname.hh \
	dnsparser.hh dnsparser.cc \
	dnswriter.cc dnswriter.hh \
	doh.hh doh.cc \
	dolog.hh \
	ednsoptions.cc ednsoptions.hh \
	ednscookies.cc ednscookies.hh \
	ednssubnet.cc ednssubnet.hh \
	fstrm_logger.cc fstrm_logger.hh \
	gettime.cc gettime.hh \
	htmlfiles.h \
	iputils.cc iputils.hh \
	libssl.cc libssl.hh \
	lock.hh \
	misc.cc misc.hh \
	mplexer.hh \
	namespaces.hh \
	pdnsexception.hh \
	protobuf.cc protobuf.hh \
	dnstap.cc dnstap.hh \
	qtype.cc qtype.hh \
	remote_logger.cc remote_logger.hh \
	pollmplexer.cc \
	sholder.hh \
	snmp-agent.cc snmp-agent.hh \
	sodcrypto.cc sodcrypto.hh \
	sstuff.hh \
	statnode.cc statnode.hh \
	tcpiohandler.cc tcpiohandler.hh \
	threadname.hh threadname.cc \
	uuid-utils.hh uuid-utils.cc \
	xpf.cc xpf.hh \
	ext/luawrapper/include/LuaContext.hpp \
	ext/json11/json11.cpp \
	ext/json11/json11.hpp \
	ext/incbin/incbin.h \
	ext/libbpf/libbpf.h

testrunner_SOURCES = \
	base64.hh \
	dns.hh \
	test-base64_cc.cc \
	test-delaypipe_hh.cc \
	test-dnscrypt_cc.cc \
	test-dnsdist_cc.cc \
	test-dnsdistdynblocks_hh.cc \
	test-dnsdistkvs_cc.cc \
	test-dnsdistpacketcache_cc.cc \
	test-dnsdistrings_cc.cc \
	test-dnsdistrules_cc.cc \
	test-dnsparser_cc.cc \
	test-iputils_hh.cc \
	test-mplexer.cc \
	cachecleaner.hh \
	circular_buffer.hh \
	dnsdist.hh \
	dnsdist-cache.cc dnsdist-cache.hh \
	dnsdist-ecs.cc dnsdist-ecs.hh \
	dnsdist-kvs.cc dnsdist-kvs.hh \
	dnsdist-rings.hh \
	dnsdist-xpf.cc dnsdist-xpf.hh \
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
	pollmplexer.cc \
	qtype.cc qtype.hh \
	sholder.hh \
	sodcrypto.cc \
	sstuff.hh \
	statnode.cc statnode.hh \
	threadname.hh threadname.cc \
	testrunner.cc \
	xpf.cc xpf.hh

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
	$(FSTRM_LIBS) \
	$(SANITIZER_FLAGS) \
	$(SYSTEMD_LIBS) \
	$(NET_SNMP_LIBS) \
	$(LIBCAP_LIBS) \
	$(IPCRYPT_LIBS)

testrunner_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(PROGRAM_LDFLAGS) \
	$(BOOST_UNIT_TEST_FRAMEWORK_LDFLAGS) \
	-pthread

testrunner_LDADD = \
	$(BOOST_UNIT_TEST_FRAMEWORK_LIBS) \
	$(LIBSODIUM_LIBS) \
	$(FSTRM_LIBS) \
	$(RT_LIBS) \
	$(SANITIZER_FLAGS) \
	$(LIBCAP_LIBS)

if HAVE_CDB
dnsdist_LDADD += $(CDB_LDFLAGS) $(CDB_LIBS)
testrunner_LDADD += $(CDB_LDFLAGS) $(CDB_LIBS)
dnsdist_SOURCES += cdb.cc cdb.hh
testrunner_SOURCES += cdb.cc cdb.hh
endif

if HAVE_RE2
dnsdist_LDADD += $(RE2_LIBS)
endif

if HAVE_LIBSSL
dnsdist_LDADD += $(LIBSSL_LIBS)
endif

if HAVE_LIBCRYPTO
dnsdist_LDADD += $(LIBCRYPTO_LDFLAGS) $(LIBCRYPTO_LIBS)
dnsdist_SOURCES += ipcipher.cc ipcipher.hh
endif

if HAVE_LMDB
dnsdist_LDADD += $(LMDB_LDFLAGS) $(LMDB_LIBS)
testrunner_LDADD += $(LMDB_LDFLAGS) $(LMDB_LIBS)
dnsdist_SOURCES += ext/lmdb-safe/lmdb-safe.cc ext/lmdb-safe/lmdb-safe.hh
testrunner_SOURCES += ext/lmdb-safe/lmdb-safe.cc ext/lmdb-safe/lmdb-safe.hh
endif

if HAVE_DNS_OVER_TLS
if HAVE_GNUTLS
dnsdist_LDADD += -lgnutls
endif
endif

if HAVE_DNS_OVER_HTTPS

if HAVE_LIBH2OEVLOOP
dnsdist_LDADD += $(LIBH2OEVLOOP_LIBS)
endif

endif

if !HAVE_LUA_HPP
BUILT_SOURCES += lua.hpp
nodist_dnsdist_SOURCES = lua.hpp
CLEANFILES += lua.hpp
endif

if HAVE_PROTOBUF
if HAVE_PROTOC
dnsmessage.pb.cc: dnsmessage.proto
	$(AM_V_GEN)$(PROTOC) -I$(srcdir) --cpp_out=./ $<

dnstap.pb.cc: dnstap.proto
	$(AM_V_GEN)$(PROTOC) -I$(srcdir) --cpp_out=./ $<

BUILT_SOURCES += dnsmessage.pb.cc dnstap.pb.cc

nodist_dnsdist_SOURCES = dnsmessage.pb.cc dnsmessage.pb.h dnstap.pb.cc dnstap.pb.h
dnsdist_LDADD += $(PROTOBUF_LIBS)

dnsdist.$(OBJEXT): dnsmessage.pb.cc dnstap.pb.cc
endif
endif

if HAVE_FREEBSD
dnsdist_SOURCES += kqueuemplexer.cc
testrunner_SOURCES += kqueuemplexer.cc
endif

if HAVE_LINUX
dnsdist_SOURCES += epollmplexer.cc
testrunner_SOURCES += epollmplexer.cc
endif

if HAVE_SOLARIS
dnsdist_SOURCES += \
        devpollmplexer.cc \
        portsmplexer.cc
testrunner_SOURCES += \
        devpollmplexer.cc \
        portsmplexer.cc
endif

MANPAGES=dnsdist.1

dist_man_MANS=$(MANPAGES)

if HAVE_VIRTUALENV
if !HAVE_MANPAGES
$(MANPAGES): %: docs/manpages/%.rst .venv
	$(AM_V_GEN).venv/bin/python -msphinx -b man docs . $<
endif # if !HAVE_MANPAGES

.venv: docs/requirements.txt
	virtualenv .venv
	.venv/bin/pip install -U pip setuptools setuptools-git
	.venv/bin/pip install -r $<

latex/dnsdist.pdf: docs/** .venv
	.venv/bin/python -msphinx -M latexpdf docs .

dnsdist.pdf: latex/dnsdist.pdf
	mv $< $@

html-docs.tar.bz2: html-docs
	tar cjf $@ $<

html-docs: docs/** .venv
	.venv/bin/python -msphinx -b html docs html-docs

all-docs: html-docs html-docs.tar.bz2 dnsdist.pdf

upload-docs: all-docs
	rsync -crv --delete --no-p --chmod=g=rwX --exclude '*~' ./html-docs/ web1.powerdns.com:/srv/www/dnsdist.org
	rsync -crv --no-p --chmod=g=rwX --exclude '*~' ./html-docs.tar.bz2 web1.powerdns.com:/srv/www/dnsdist.org
	rsync -crv --no-p --chmod=g=rwX --exclude '*~' ./dnsdist.pdf web1.powerdns.com:/srv/www/dnsdist.org

else # if HAVE_VIRTUALENV
$(MANPAGES):
	@echo "You need virtualenv to generate the manpages"
	exit 1

html-docs: %: docs/manpages/%.rst .venv
	@echo "You need virtualenv to generate the HTML documentation"
	exit 1

dnsdist.pdf:
	@echo "You need virtualenv to generate the pdf documentation"
	exit 1
endif

if HAVE_SYSTEMD
dnsdist.service: dnsdist.service.in
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

dnsdist@.service: dnsdist.service
	$(AM_V_GEN)sed -e 's!/dnsdist !&--config $(sysconfdir)/dnsdist-%i.conf !' < $< >$@

systemdsystemunitdir = $(SYSTEMD_DIR)

systemdsystemunit_DATA = \
	dnsdist.service \
	dnsdist@.service

CLEANFILES += \
	dnsdist.service \
	dnsdist@.service
endif

if !HAVE_LUA_HPP
include lua_hpp.mk
endif
