AM_CXXFLAGS=-D_GNU_SOURCE -DSYSCONFDIR=\"@sysconfdir@\" -DBINDIR=\"@bindir@\" -DLOCALSTATEDIR=\"@socketdir@\" -Ibackends/bind
AM_CPPFLAGS=-Ibackends/bind

EXTRA_DIST = codedocs/Makefile codedocs/doxygen.conf docs/Makefile \
docs/gslb-operations.sgml docs/powerdns-case.sgml docs/powerdns-install.sgml \
docs/powerdns-overview.sgml docs/powerdns-technical.sgml extra/Makefile \
extra/null.c pdns.spec release-scripts/ docs/pdns.sgml \
choosepaths mtasker.cc 

noinst_SCRIPTS = pdns
sysconf_DATA = pdns.conf-dist 

bin_PROGRAMS = pdns_control # binpatch # syncres #   resolver syncres 
sbin_PROGRAMS = pdns_server 
#pdns.conf-dist: pdns_server
#	-./pdns_server --config > $@

pdns_server_SOURCES=dnspacket.cc nameserver.cc tcpreceiver.hh \
qtype.cc logger.cc arguments.cc packethandler.cc tcpreceiver.cc \
packetcache.cc statbag.cc ahuexception.hh arguments.hh distributor.hh \
dns.hh dnsbackend.hh dnsbackend.cc dnspacket.hh dynmessenger.hh lock.hh logger.hh \
nameserver.hh packetcache.hh packethandler.hh qtype.hh statbag.hh \
ueberbackend.hh pdns.conf-dist ws.hh ws.cc webserver.cc webserver.hh \
session.cc session.hh misc.cc misc.hh receiver.cc ueberbackend.cc \
dynlistener.cc dynlistener.hh  dynhandler.cc dynhandler.hh  \
resolver.hh resolver.cc communicator.cc communicator.hh dnsproxy.cc \
dnsproxy.hh randombackend.cc unix_utility.cc common_startup.cc \
utility.hh iputils.hh common_startup.hh \
backends/bind/bindbackend.cc backends/bind/zoneparser2.cc \
backends/bind/bindparser.cc backends/bind/bindlexer.c \
backends/bind/huffman.cc

#
pdns_server_LDFLAGS=-rdynamic @LIBDL@ @moduleobjects@ @modulelibs@ 
pdns_server_INCLUDES=


#resolver_SOURCES=resolver.cc resolver.hh misc.cc unix_utility.cc qtype.cc \
#logger.cc statbag.cc dnspacket.cc arguments.cc  tres.cc

#syncres_SOURCES=syncres.cc resolver.hh misc.cc unix_utility.cc qtype.cc \
#logger.cc statbag.cc dnspacket.cc arguments.cc  lwres.cc recns.cc lwres.hh \
#mtasker.hh 

pdns_control_SOURCES=dynloader.cc dynmessenger.cc  arguments.cc logger.cc statbag.cc misc.cc unix_utility.cc
pdns_control_INCLUDES=path.hh
pdns_control_LDFLAGS=

# binpatch_SOURCES=binpatch.cc 

SUBDIRS= codedocs backends extra .

