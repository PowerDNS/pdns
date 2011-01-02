AM_CXXFLAGS=-DSYSCONFDIR=\"@sysconfdir@\" -DLIBDIR=\"@libdir@\" -DLOCALSTATEDIR=\"@socketdir@\" -Ibackends/bind @THREADFLAGS@ -I/usr/include/lua5.1 -Iext/polarssl/include
AM_CPPFLAGS=-Ibackends/bind $(BOOST_CPPFLAGS) @THREADFLAGS@

EXTRA_DIST = docs/Makefile docs/expand \
docs/gslb-operations.sgml docs/powerdns-case.sgml docs/powerdns-install.sgml \
docs/powerdns-overview.sgml docs/powerdns-technical.sgml  \
docs/pdns.sgml mtasker.cc inflighter.cc \
docs/pdns_control.8  docs/pdns_server.8 docs/zone2sql.8

SUBDIRS= ext/polarssl backends 

noinst_SCRIPTS = pdns
sysconf_DATA = pdns.conf-dist 

if RECURSOR
sbin_PROGRAMS = pdns_server pdns_recursor
bin_PROGRAMS = pdns_control  rec_control pdnssec dnsreplay
else
sbin_PROGRAMS = pdns_server 
bin_PROGRAMS = pdns_control pdnssec dnsreplay
endif

EXTRA_PROGRAMS=pdns_recursor sdig tsig-tests speedtest pdns_control dnsscope dnsgram \
toysdig dnsdemog dnswasher dnsscan dnslog nproxy notify pdnssec dnsbulktest # dnslabel # tcptorture

pdns_server_SOURCES=dnspacket.cc nameserver.cc tcpreceiver.hh \
qtype.cc logger.cc arguments.cc packethandler.cc tcpreceiver.cc \
packetcache.cc statbag.cc ahuexception.hh arguments.hh distributor.hh \
dns.hh dnsbackend.hh dnsbackend.cc dnspacket.hh dynmessenger.hh lock.hh logger.hh \
nameserver.hh packetcache.hh packethandler.hh qtype.hh statbag.hh \
ueberbackend.hh pdns.conf-dist ws.hh ws.cc webserver.cc webserver.hh \
session.cc session.hh misc.cc misc.hh receiver.cc ueberbackend.cc \
dynlistener.cc dynlistener.hh  dynhandler.cc dynhandler.hh  \
resolver.hh resolver.cc slavecommunicator.cc mastercommunicator.cc communicator.cc communicator.hh dnsproxy.cc \
dnsproxy.hh randombackend.cc unix_utility.cc common_startup.cc \
utility.hh iputils.hh common_startup.hh unix_semaphore.cc \
backends/bind/bindbackend2.cc  \
backends/bind/bindparser.cc backends/bind/bindlexer.c \
backends/gsql/gsqlbackend.cc \
backends/gsql/gsqlbackend.hh backends/gsql/ssql.hh \
base64.cc sillyrecords.cc \
base64.hh zoneparser-tng.cc dnsrecords.cc dnswriter.cc \
rcpgenerator.cc	dnsparser.cc dns_random.hh aes/aescpp.h \
aes/aescrypt.c aes/aes.h aes/aeskey.c aes/aes_modes.c aes/aesopt.h \
aes/aestab.c aes/aestab.h aes/brg_endian.h aes/brg_types.h aes/dns_random.cc \
randomhelper.cc namespaces.hh nsecrecords.cc base32.cc dbdnsseckeeper.cc dnssecinfra.cc \
dnsseckeeper.hh dnssecinfra.hh base32.hh dns.cc

#
pdns_server_LDFLAGS=@moduleobjects@ @modulelibs@ @DYNLINKFLAGS@ @LIBDL@ @THREADFLAGS@ $(BOOST_FILESYSTEM_LDFLAGS) $(BOOST_SYSTEM_LDFLAGS) -Lext/polarssl/library
pdns_server_LDADD=$(BOOST_FILESYSTEM_LIBS) $(BOOST_SYSTEM_LIBS) -lpolarssl
  


pdnssec_SOURCES=pdnssec.cc dbdnsseckeeper.cc sstuff.hh dnsparser.cc dnsparser.hh dnsrecords.cc dnswriter.cc dnswriter.hh \
        misc.cc misc.hh rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh unix_utility.cc \
	logger.cc statbag.cc qtype.cc sillyrecords.cc nsecrecords.cc dnssecinfra.cc dnssecinfra.hh \
        base32.cc  ueberbackend.cc dnsbackend.cc arguments.cc packetcache.cc dnspacket.cc  \
        backends/bind/bindbackend2.cc  \
	backends/bind/bindparser.cc backends/bind/bindlexer.c \
	backends/gsql/gsqlbackend.cc \
	backends/gsql/gsqlbackend.hh backends/gsql/ssql.hh zoneparser-tng.cc \
	dynlistener.cc dns.cc

pdnssec_LDFLAGS=@moduleobjects@ @modulelibs@ @DYNLINKFLAGS@ @LIBDL@ @THREADFLAGS@ -Lext/polarssl/library/ 
pdnssec_LDADD=$(BOOST_FILESYSTEM_LIBS) $(BOOST_SYSTEM_LIBS) -lpolarssl $(BOOST_PROGRAM_OPTIONS_LIBS)

sdig_SOURCES=sdig.cc sstuff.hh dnsparser.cc dnsparser.hh dnsrecords.cc dnswriter.cc dnswriter.hh \
	misc.cc misc.hh rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh unix_utility.cc \
	logger.cc statbag.cc qtype.cc sillyrecords.cc nsecrecords.cc base32.cc

toysdig_SOURCES=toysdig.cc sstuff.hh dnsparser.cc dnsparser.hh dnsrecords.cc dnswriter.cc dnswriter.hh \
	misc.cc misc.hh rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh unix_utility.cc \
	logger.cc statbag.cc qtype.cc sillyrecords.cc nsecrecords.cc base32.cc dnslabel.cc dnslabel.hh


#tcptorture_SOURCES=tcptorture.cc sstuff.hh dnsparser.cc dnsparser.hh dnsrecords.cc dnswriter.cc dnswriter.hh \
#	misc.cc misc.hh rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh unix_utility.cc \
#	logger.cc statbag.cc qtype.cc sillyrecords.cc nsecrecords.cc base32.cc


tsig_tests_SOURCES=tsig-tests.cc sstuff.hh dnsparser.cc dnsparser.hh dnsrecords.cc dnswriter.cc dnswriter.hh \
	misc.cc misc.hh rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh unix_utility.cc \
	logger.cc statbag.cc qtype.cc sillyrecords.cc md5.cc


speedtest_SOURCES=speedtest.cc dnsparser.cc dnsparser.hh dnsrecords.cc dnswriter.cc dnswriter.hh \
	misc.cc misc.hh rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh unix_utility.cc \
	qtype.cc sillyrecords.cc logger.cc statbag.cc nsecrecords.cc base32.cc

dnswasher_SOURCES=dnswasher.cc misc.cc unix_utility.cc qtype.cc \
	logger.cc statbag.cc  dnspcap.cc dnspcap.hh dnsparser.hh 

dnswasher_LDFLAGS= @DYNLINKFLAGS@ @THREADFLAGS@

dnsbulktest_SOURCES=dnsbulktest.cc misc.cc unix_utility.cc qtype.cc logger.cc statbag.cc dnsparser.cc \
	dnsrecords.cc dnswriter.cc rcpgenerator.cc base32.cc base64.cc sillyrecords.cc nsecrecords.cc 
dnsbulktest_LDFLAGS= @DYNLINKFLAGS@ @THREADFLAGS@


# unix_utility.cc

dnsscan_SOURCES=dnsscan.cc misc.cc  qtype.cc anadns.hh \
	logger.cc statbag.cc  dnspcap.cc dnspcap.hh dnsparser.cc dnsrecords.cc dnsparser.hh  \
	rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh dnswriter.cc dnswriter.hh \
	unix_utility.cc utility.hh		

dnslog_SOURCES=dnslog.cc misc.cc  qtype.cc anadns.hh \
	logger.cc statbag.cc  dnspcap.cc dnspcap.hh dnsparser.cc dnsrecords.cc dnsparser.hh  \
	rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh dnswriter.cc dnswriter.hh \
	unix_utility.cc utility.hh		

#socketbench_SOURCES=socketbench.cc qtype.cc misc.cc unix_utility.cc\
#	 logger.cc statbag.cc epollmplexer.cc

dnsreplay_SOURCES=dnsreplay.cc misc.cc  qtype.cc anadns.hh \
	logger.cc statbag.cc  dnspcap.cc dnspcap.hh dnsparser.cc dnsrecords.cc dnsparser.hh  \
	rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh dnswriter.cc dnswriter.hh \
	unix_utility.cc utility.hh sillyrecords.cc nsecrecords.cc base32.cc

dnsreplay_LDFLAGS= @DYNLINKFLAGS@ @THREADFLAGS@ $(BOOST_FILESYSTEM_LDFLAGS) $(BOOST_PROGRAM_OPTIONS_LDFLAGS)
dnsreplay_LDADD=$(BOOST_FILESYSTEM_LIBS) $(BOOST_PROGRAM_OPTIONS_LIBS)

nproxy_SOURCES=nproxy.cc dnsparser.cc dnsrecords.cc dnsparser.hh  \
	rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh dnswriter.cc dnswriter.hh \
	sillyrecords.cc selectmplexer.cc  mplexer.hh

nproxy_LDFLAGS= @DYNLINKFLAGS@ @THREADFLAGS@ $(BOOST_FILESYSTEM_LDFLAGS) $(BOOST_PROGRAM_OPTIONS_LDFLAGS)
nproxy_LDADD=$(BOOST_FILESYSTEM_LIBS) $(BOOST_PROGRAM_OPTIONS_LIBS)

notify_SOURCES=notify.cc dnsparser.cc dnsrecords.cc dnsparser.hh  \
	rcpgenerator.cc rcpgenerator.hh base64.cc base64.hh dnswriter.cc dnswriter.hh \
	sillyrecords.cc selectmplexer.cc nsecrecords.cc base32.cc misc.cc unix_utility.cc \
	logger.cc qtype.cc statbag.cc

notify_LDFLAGS= @DYNLINKFLAGS@ @THREADFLAGS@ $(BOOST_FILESYSTEM_LDFLAGS) $(BOOST_PROGRAM_OPTIONS_LDFLAGS)
notify_LDADD=$(BOOST_FILESYSTEM_LIBS) $(BOOST_PROGRAM_OPTIONS_LIBS)

dnsscope_SOURCES=dnsscope.cc misc.cc unix_utility.cc qtype.cc \
	logger.cc statbag.cc  dnspcap.cc dnspcap.hh dnsparser.cc dnsrecords.cc \
	base64.cc base64.hh dnswriter.cc dnswriter.hh rcpgenerator.cc rcpgenerator.hh \
	utility.hh dnsparser.hh sillyrecords.cc nsecrecords.cc base32.cc

dnsscope_LDFLAGS= @DYNLINKFLAGS@ @THREADFLAGS@

dnsgram_SOURCES=dnsgram.cc misc.cc unix_utility.cc qtype.cc \
	logger.cc statbag.cc  dnspcap.cc dnspcap.hh dnsparser.cc dnsrecords.cc \
	base64.cc base64.hh dnswriter.cc dnswriter.hh rcpgenerator.cc rcpgenerator.hh \
	utility.hh dnsparser.hh sillyrecords.cc nsecrecords.cc base32.cc

dnsdemog_SOURCES=dnsdemog.cc misc.cc unix_utility.cc qtype.cc \
	logger.cc statbag.cc  dnspcap.cc dnspcap.hh dnsparser.cc dnsrecords.cc \
	base64.cc base64.hh dnswriter.cc dnswriter.hh rcpgenerator.cc rcpgenerator.hh \
	utility.hh dnsparser.hh sillyrecords.cc

rec_control_SOURCES=rec_channel.cc rec_channel.hh rec_control.cc arguments.cc arguments.hh misc.cc qtype.cc \
	unix_utility.cc logger.cc statbag.cc

pdns_recursor_SOURCES=syncres.cc resolver.hh misc.cc unix_utility.cc qtype.cc \
logger.cc statbag.cc arguments.cc  lwres.cc pdns_recursor.cc reczones.cc lwres.hh \
mtasker.hh syncres.hh recursor_cache.cc recursor_cache.hh dnsparser.cc \
dnswriter.cc dnswriter.hh dnsrecords.cc dnsrecords.hh rcpgenerator.cc rcpgenerator.hh \
base64.cc base64.hh zoneparser-tng.cc zoneparser-tng.hh rec_channel.cc rec_channel.hh \
rec_channel_rec.cc selectmplexer.cc epollmplexer.cc sillyrecords.cc htimer.cc htimer.hh \
aes/dns_random.cc aes/aescrypt.c aes/aeskey.c aes/aestab.c aes/aes_modes.c \
lua-pdns-recursor.cc lua-pdns-recursor.hh randomhelper.cc  \
recpacketcache.cc recpacketcache.hh dns.cc nsecrecords.cc base32.cc

#../modules/gmysqlbackend/smysql.cc 

pdns_recursor_LDFLAGS= -llua5.1 
pdns_recursor_LDADD=

pdns_control_SOURCES=dynloader.cc dynmessenger.cc  arguments.cc logger.cc statbag.cc \
misc.cc unix_utility.cc qtype.cc

pdns_control_INCLUDES=path.hh
pdns_control_LDFLAGS=@THREADFLAGS@

# binpatch_SOURCES=binpatch.cc 


