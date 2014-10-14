AM_CPPFLAGS += \
	-I../../pdns/ext/rapidjson/include \
	$(YAHTTP_CFLAGS) \
	$(POLARSSL_CFLAGS) \
	$(LIBZMQ_CFLAGS)

AM_LDFLAGS = $(THREADFLAGS)

SUBDIRS = ../../pdns/ext/yahttp

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
	test_remotebackend_pipe \
	test_remotebackend_unix \
	test_remotebackend_http \
	test_remotebackend_post \
	test_remotebackend_json \
	test_remotebackend_zeromq

EXTRA_LTLIBRARIES = libtestremotebackend.la

clean-local:
	rm -f $(EXTRA_PROGRAMS)

pkglib_LTLIBRARIES = libremotebackend.la

libremotebackend_la_SOURCES = \
	remotebackend.hh \
	remotebackend.cc \
	unixconnector.cc \
	httpconnector.cc \
	pipeconnector.cc \
	zmqconnector.cc

libremotebackend_la_LDFLAGS = -module -avoid-version

libremotebackend_la_LIBADD = $(YAHTTP_LIBS)

if REMOTEBACKEND_ZEROMQ
libremotebackend_la_LIBADD += $(LIBZMQ_LIBS)
endif

if UNIT_TESTS
TESTS_ENVIRONMENT = \
	env BOOST_TEST_LOG_LEVEL=message REMOTEBACKEND_ZEROMQ=$(REMOTEBACKEND_ZEROMQ) ./testrunner.sh

TESTS = \
	test_remotebackend_pipe \
	test_remotebackend_unix \
	test_remotebackend_http \
	test_remotebackend_post \
	test_remotebackend_json \
	test_remotebackend_zeromq
endif

BUILT_SOURCES = ../../pdns/dnslabeltext.cc

../../pdns/dnslabeltext.cc: ../../pdns/dnslabeltext.rl
	$(MAKE) -C ../../pdns dnslabeltext.cc

libtestremotebackend_la_SOURCES = \
	../../pdns/arguments.hh ../../pdns/arguments.cc \
	../../pdns/base32.cc \
	../../pdns/base64.cc \
	../../pdns/dnsbackend.hh ../../pdns/dnsbackend.cc \
	../../pdns/dnslabeltext.cc \
	../../pdns/dnspacket.cc \
	../../pdns/dnsparser.cc \
	../../pdns/dnsrecords.cc \
	../../pdns/dnssecinfra.cc \
	../../pdns/ednssubnet.cc \
	../../pdns/json.hh ../../pdns/json.cc \
	../../pdns/logger.cc \
	../../pdns/misc.cc \
	../../pdns/nsecrecords.cc \
	../../pdns/packetcache.hh ../../pdns/packetcache.cc \
	../../pdns/qtype.cc \
	../../pdns/sillyrecords.cc \
	../../pdns/statbag.cc \
	../../pdns/ueberbackend.hh ../../pdns/ueberbackend.cc \
	../../pdns/dns.hh ../../pdns/dns.cc \
	../../pdns/dns_random.cc \
	../../pdns/dnswriter.cc \
	../../pdns/nameserver.cc \
	../../pdns/rcpgenerator.cc \
	../../pdns/unix_utility.cc \
	httpconnector.cc \
	pipeconnector.cc \
	unixconnector.cc \
	zmqconnector.cc \
	remotebackend.hh remotebackend.cc

libtestremotebackend_la_CPPFLAGS = $(AM_CPPFLAGS)

libtestremotebackend_la_LIBADD = \
	$(YAHTTP_LIBS) \
	$(POLARSSL_LIBS) \
	$(BOOST_UNIT_TEST_FRAMEWORK_LIBS) \
	$(BOOST_SERIALIZATION_LIBS) \
	$(BOOST_PROGRAM_OPTIONS_LIBS)

libtestremotebackend_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(BOOST_UNIT_TEST_FRAMEWORK_LDFLAGS)

if REMOTEBACKEND_ZEROMQ
libtestremotebackend_la_LIBADD += $(LIBZMQ_LIBS)
endif

if PKCS11
libtestremotebackend_la_SOURCES += \
	../../pdns/pkcs11signers.hh \
	../../pdns/pkcs11signers.cc

libtestremotebackend_la_LIBADD += \
	$(P11KIT1_LIBS) \
	$(LIBDL)

libtestremotebackend_la_CPPFLAGS += \
	$(P11KIT1_CFLAGS)
endif

test_remotebackend_http_SOURCES = \
	test-remotebackend.cc \
	test-remotebackend-http.cc \
	test-remotebackend-keys.hh

test_remotebackend_http_LDADD = libtestremotebackend.la

test_remotebackend_json_SOURCES = \
	test-remotebackend.cc \
	test-remotebackend-json.cc \
	test-remotebackend-keys.hh

test_remotebackend_json_LDADD = libtestremotebackend.la

test_remotebackend_pipe_SOURCES = \
	test-remotebackend.cc \
	test-remotebackend-pipe.cc \
	test-remotebackend-keys.hh 

test_remotebackend_pipe_LDADD = libtestremotebackend.la

test_remotebackend_post_SOURCES = \
	test-remotebackend.cc \
	test-remotebackend-post.cc \
	test-remotebackend-keys.hh

test_remotebackend_post_LDADD = libtestremotebackend.la

test_remotebackend_unix_SOURCES = \
	test-remotebackend.cc \
	test-remotebackend-unix.cc \
	test-remotebackend-keys.hh

test_remotebackend_unix_LDADD = libtestremotebackend.la

test_remotebackend_zeromq_SOURCES = \
	test-remotebackend.cc \
	test-remotebackend-zeromq.cc \
	test-remotebackend-keys.hh

test_remotebackend_zeromq_LDADD = libtestremotebackend.la

