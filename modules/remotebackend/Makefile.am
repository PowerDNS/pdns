AM_CPPFLAGS += \
	-I$(top_srcdir)/ext/json11 \
	$(YAHTTP_CFLAGS) \
	$(LIBCRYPTO_CFLAGS) \
	$(LIBZMQ_CFLAGS)

if LUA
AM_CPPFLAGS +=$(LUA_CFLAGS)
endif

if LIBSODIUM
AM_CPPFLAGS +=$(LIBSODIUM_CFLAGS)
endif

AM_LDFLAGS = $(THREADFLAGS)

JSON11_LIBS = $(top_builddir)/ext/json11/libjson11.la

EXTRA_DIST = \
	OBJECTFILES \
	OBJECTLIBS \
	testrunner.sh \
	unittest_http.rb \
	unittest_json.rb \
	unittest_pipe.rb \
	unittest_zeromq.rb \
	unittest_post.rb \
	unittest.rb \
	Gemfile \
	Gemfile.lock

EXTRA_PROGRAMS = \
	remotebackend_pipe.test \
	remotebackend_unix.test \
	remotebackend_http.test \
	remotebackend_post.test \
	remotebackend_json.test \
	remotebackend_zeromq.test

EXTRA_LTLIBRARIES = libtestremotebackend.la

clean-local:
	rm -f $(EXTRA_PROGRAMS)

pkglib_LTLIBRARIES = libremotebackend.la

libremotebackend_la_SOURCES = \
	httpconnector.cc \
	pipeconnector.cc \
	remotebackend.cc \
	remotebackend.hh \
	unixconnector.cc \
	zmqconnector.cc

libremotebackend_la_LDFLAGS = -module -avoid-version

libremotebackend_la_LIBADD = $(YAHTTP_LIBS) $(JSON11_LIBS)

if REMOTEBACKEND_ZEROMQ
libremotebackend_la_LIBADD += $(LIBZMQ_LIBS)
endif

TESTS_ENVIRONMENT = \
	BOOST_TEST_LOG_LEVEL=message; \
	export BOOST_TEST_LOG_LEVEL; \
	REMOTEBACKEND_ZEROMQ=$(REMOTEBACKEND_ZEROMQ); \
	export REMOTEBACKEND_ZEROMQ;

TEST_EXTENSIONS = .test

TEST_LOG_COMPILER = $(abs_srcdir)/testrunner.sh

RECHECK_LOGS = \
	$(TEST_LOGS) \
	remotebackend_http_server.log \
	remotebackend_post_server.log \
	remotebackend_json_server.log \
	remotebackend_zeromq_server.log

## The http, post and json test are using the same TCP port.
## To prevent "Address already in use - bind(2) (Errno::EADDRINUSE)"
## errors when running `make check` in parallel, we need to specify
## an order
remotebackend_post.log: remotebackend_http.log

remotebackend_json.log: remotebackend_http.log remotebackend_post.log

if BACKEND_UNIT_TESTS
TESTS = \
	remotebackend_pipe.test \
	remotebackend_unix.test \
	remotebackend_http.test \
	remotebackend_post.test \
	remotebackend_json.test \
	remotebackend_zeromq.test

endif

BUILT_SOURCES = ../../pdns/dnslabeltext.cc

../../pdns/dnslabeltext.cc: ../../pdns/dnslabeltext.rl
	$(MAKE) -C ../../pdns dnslabeltext.cc

libtestremotebackend_la_SOURCES = \
	../../pdns/arguments.hh ../../pdns/arguments.cc \
	../../pdns/auth-packetcache.cc ../../pdns/auth-packetcache.hh \
	../../pdns/auth-querycache.cc ../../pdns/auth-querycache.hh \
	../../pdns/auth-zonecache.cc ../../pdns/auth-zonecache.hh \
	../../pdns/base32.cc \
	../../pdns/base64.cc \
	../../pdns/dns.hh ../../pdns/dns.cc \
	../../pdns/dns_random_urandom.cc \
	../../pdns/dnsbackend.hh ../../pdns/dnsbackend.cc \
	../../pdns/dnslabeltext.cc \
	../../pdns/dnsname.cc ../../pdns/dnsname.hh \
	../../pdns/dnspacket.cc \
	../../pdns/dnsparser.cc \
	../../pdns/dnsrecords.cc \
	../../pdns/dnssecinfra.cc \
	../../pdns/dnswriter.cc \
	../../pdns/ednscookies.cc \
	../../pdns/ednsoptions.cc ../../pdns/ednsoptions.hh \
	../../pdns/ednssubnet.cc \
	../../pdns/iputils.cc \
	../../pdns/json.hh ../../pdns/json.cc \
	../../pdns/logger.cc \
	../../pdns/misc.cc \
	../../pdns/nameserver.cc \
	../../pdns/nsecrecords.cc \
	../../pdns/packetcache.hh \
	../../pdns/qtype.cc \
	../../pdns/rcpgenerator.cc \
	../../pdns/shuffle.hh ../../pdns/shuffle.cc \
	../../pdns/sillyrecords.cc \
	../../pdns/statbag.cc \
	../../pdns/svc-records.cc ../../pdns/svc-records.hh \
	../../pdns/ueberbackend.hh ../../pdns/ueberbackend.cc \
	../../pdns/unix_utility.cc \
	httpconnector.cc \
	pipeconnector.cc \
	remotebackend.hh remotebackend.cc \
	unixconnector.cc \
	zmqconnector.cc

libtestremotebackend_la_CPPFLAGS = $(AM_CPPFLAGS)

libtestremotebackend_la_LIBADD = \
	$(YAHTTP_LIBS) \
	$(LIBCRYPTO_LIBS) \
	$(BOOST_UNIT_TEST_FRAMEWORK_LIBS) \
	$(BOOST_PROGRAM_OPTIONS_LIBS) \
	$(LIBDL) $(JSON11_LIBS)

libtestremotebackend_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(BOOST_UNIT_TEST_FRAMEWORK_LDFLAGS)

if LIBSODIUM
libtestremotebackend_la_LIBADD += $(LIBSODIUM_LIBS)
endif

if REMOTEBACKEND_ZEROMQ
libtestremotebackend_la_LIBADD += $(LIBZMQ_LIBS)
endif

if PKCS11
libtestremotebackend_la_SOURCES += \
	../../pdns/pkcs11signers.hh \
	../../pdns/pkcs11signers.cc

libtestremotebackend_la_LIBADD += \
	$(P11KIT1_LIBS)

libtestremotebackend_la_CPPFLAGS += \
	$(P11KIT1_CFLAGS)
endif

remotebackend_http_test_SOURCES = \
	test-remotebackend-http.cc \
	test-remotebackend-keys.hh \
	test-remotebackend.cc

remotebackend_http_test_LDADD = libtestremotebackend.la

remotebackend_json_test_SOURCES = \
	test-remotebackend-json.cc \
	test-remotebackend-keys.hh \
	test-remotebackend.cc

remotebackend_json_test_LDADD = libtestremotebackend.la

remotebackend_pipe_test_SOURCES = \
	test-remotebackend-keys.hh \
	test-remotebackend-pipe.cc \
	test-remotebackend.cc

remotebackend_pipe_test_LDADD = libtestremotebackend.la

remotebackend_post_test_SOURCES = \
	test-remotebackend-keys.hh \
	test-remotebackend-post.cc \
	test-remotebackend.cc

remotebackend_post_test_LDADD = libtestremotebackend.la

remotebackend_unix_test_SOURCES = \
	test-remotebackend-keys.hh \
	test-remotebackend-unix.cc \
	test-remotebackend.cc

remotebackend_unix_test_LDADD = libtestremotebackend.la

remotebackend_zeromq_test_SOURCES = \
	test-remotebackend-keys.hh \
	test-remotebackend-zeromq.cc \
	test-remotebackend.cc

remotebackend_zeromq_test_LDADD = libtestremotebackend.la
