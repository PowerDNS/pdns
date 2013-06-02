AM_CPPFLAGS=@THREADFLAGS@ $(BOOST_CPPFLAGS) $(LIBCURL_CFLAGS) -I../../pdns/ext/rapidjson/include
#if !ALLSTATIC
#install-exec-local:
#       install .lib/libremotebackend.so.0.0.0 @libdir@
#endif

EXTRA_DIST=OBJECTFILES OBJECTLIBS
EXTRA_PROGRAMS=test_remotebackend_pipe test_remotebackend_http
EXTRA_LTLIBRARIES=libtestremotebackend.la

lib_LTLIBRARIES = libremotebackend.la 

libremotebackend_la_SOURCES=remotebackend.hh remotebackend.cc unixconnector.cc httpconnector.cc pipeconnector.cc 

libremotebackend_la_LDFLAGS=-module -avoid-version
libremotebackend_la_LIBS=$(LIBCURL_LIBS)

TESTS_ENVIRONMENT = env BOOST_TEST_LOG_LEVEL=message REMOTEBACKEND_HTTP=$(REMOTEBACKEND_HTTP) ./testrunner.sh 
TESTS=test_remotebackend_pipe test_remotebackend_http

BUILT_SOURCES=../../pdns/dnslabeltext.cc

../../pdns/dnslabeltext.cc: ../../pdns/dnslabeltext.rl
	make -C ../../pdns dnslabeltext.cc

libtestremotebackend_la_SOURCES=../../pdns/dnsbackend.hh ../../pdns/dnsbackend.cc ../../pdns/ueberbackend.hh ../../pdns/ueberbackend.cc \
        ../../pdns/nameserver.cc ../../pdns/misc.cc ../../pdns/arguments.hh \
        ../../pdns/unix_utility.cc ../../pdns/logger.cc ../../pdns/statbag.cc ../../pdns/arguments.hh ../../pdns/arguments.cc ../../pdns/qtype.cc ../../pdns/dnspacket.cc \
        ../../pdns/dnswriter.cc ../../pdns/base64.cc ../../pdns/base32.cc ../../pdns/dnsrecords.cc ../../pdns/dnslabeltext.cc ../../pdns/dnsparser.cc \
        ../../pdns/rcpgenerator.cc ../../pdns/ednssubnet.cc ../../pdns/nsecrecords.cc ../../pdns/sillyrecords.cc ../../pdns/dnssecinfra.cc \
        ../../pdns/aes/dns_random.cc ../../pdns/packetcache.hh ../../pdns/packetcache.cc \
        ../../pdns/aes/aescpp.h ../../pdns/dns.hh ../../pdns/dns.cc ../../pdns/json.hh ../../pdns/json.cc \
        ../../pdns/aes/aescrypt.c ../../pdns/aes/aes.h ../../pdns/aes/aeskey.c ../../pdns/aes/aes_modes.c ../../pdns/aes/aesopt.h \
        ../../pdns/aes/aestab.c ../../pdns/aes/aestab.h ../../pdns/aes/brg_endian.h ../../pdns/aes/brg_types.h ../pipebackend/coprocess.cc \
        remotebackend.hh remotebackend.cc unixconnector.cc httpconnector.cc pipeconnector.cc

libtestremotebackend_la_CFLAGS=$(BOOST_CPPFLAGS) @THREADFLAGS@ $(LIBCURL_CFLAGS) -g -O0 -I../../pdns
libtestremotebackend_la_CXXFLAGS=$(BOOST_CPPFLAGS) @THREADFLAGS@ $(LIBCURL_CFLAGS) -g -O0 -I../../pdns

test_remotebackend_pipe_SOURCES=test-remotebackend.cc test-remotebackend-pipe.cc 

test_remotebackend_http_SOURCES=test-remotebackend.cc test-remotebackend-http.cc ../../config.h

test_remotebackend_pipe_CFLAGS=$(BOOST_CPPFLAGS) @THREADFLAGS@ $(LIBCURL_CFLAGS) -g -O0 -I../../pdns
test_remotebackend_pipe_CXXFLAGS=$(BOOST_CPPFLAGS) @THREADFLAGS@ $(LIBCURL_CFLAGS) -g -O0 -I../../pdns
test_remotebackend_pipe_LDADD=libtestremotebackend.la @DYNLINKFLAGS@ @THREADFLAGS@ $(BOOST_UNIT_TEST_FRAMEWORK_LDFLAGS) ../../pdns/ext/polarssl-1.1.2/library/libpolarssl.a $(BOOST_UNIT_TEST_FRAMEWORK_LIBS) $(BOOST_SERIALIZATION_LIBS) $(BOOST_PROGRAM_OPTIONS_LIBS) @LIBDL@ $(LIBCURL_LIBS)

test_remotebackend_http_CFLAGS=$(BOOST_CPPFLAGS) @THREADFLAGS@ $(LIBCURL_CFLAGS) -g -O0 -I../../pdns
test_remotebackend_http_CXXFLAGS=$(BOOST_CPPFLAGS) @THREADFLAGS@ $(LIBCURL_CFLAGS) -g -O0 -I../../pdns
test_remotebackend_http_LDADD=libtestremotebackend.la @DYNLINKFLAGS@ @THREADFLAGS@ $(BOOST_UNIT_TEST_FRAMEWORK_LDFLAGS) ../../pdns/ext/polarssl-1.1.2/library/libpolarssl.a $(BOOST_UNIT_TEST_FRAMEWORK_LIBS) $(BOOST_SERIALIZATION_LIBS) $(BOOST_PROGRAM_OPTIONS_LIBS) @LIBDL@ $(LIBCURL_LIBS)
