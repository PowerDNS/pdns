AM_CXXFLAGS=-DSYSCONFDIR=\"@sysconfdir@\" -DLIBDIR=\"@libdir@\" -DLOCALSTATEDIR=\"@socketdir@\" -Ibackends/bind 
AM_CPPFLAGS=-Ibackends/bind @THREADFLAGS@

EXTRA_DIST = docs/Makefile \
docs/gslb-operations.sgml docs/powerdns-case.sgml docs/powerdns-install.sgml \
docs/powerdns-overview.sgml docs/powerdns-technical.sgml  \
docs/pdns.sgml mtasker.cc \
docs/pdns_control.8  docs/pdns_server.8 docs/zone2sql.8

noinst_SCRIPTS = pdns
sysconf_DATA = pdns.conf-dist 

if RECURSOR
sbin_PROGRAMS = pdns_server pdns_recursor
else
sbin_PROGRAMS = pdns_server 
endif

bin_PROGRAMS = pdns_control  

EXTRA_PROGRAMS=pdns_recursor sdig pdns_control qgen dnswasher dnsscope dnsreplay

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
backends/bind/bindbackend2.cc backends/bind/zoneparser2.cc \
backends/bind/bindparser.cc backends/bind/bindlexer.c \
backends/bind/huffman.cc backends/gsql/gsqlbackend.cc \
backends/gsql/gsqlbackend.hh backends/gsql/ssql.hh \
sillyrecords.cc backends/bind/bindbackend.cc

#
pdns_server_LDFLAGS= @moduleobjects@ @modulelibs@ @DYNLINKFLAGS@ @LIBDL@ @THREADFLAGS@
pdns_server_INCLUDES=

sdig_SOURCES=sdig.cc sstuff.hh dnsparser.cc dnsparser.hh dnsrecords.cc


qgen_SOURCES=resolver.cc resolver.hh misc.cc unix_utility.cc qtype.cc \
	logger.cc statbag.cc dnspacket.cc arguments.cc  qgen.cc \
	 sillyrecords.cc

qgen_LDFLAGS= @THREADFLAGS@ @DYNLINKFLAGS@ -lboost_regex

dnswasher_SOURCES=dnswasher.cc misc.cc unix_utility.cc qtype.cc \
	logger.cc statbag.cc  dnspcap.cc dnspcap.hh dnsparser.hh 

dnswasher_LDFLAGS= @THREADFLAGS@ @DYNLINKFLAGS@ 

dnsreplay_SOURCES=dnsreplay.cc misc.cc unix_utility.cc qtype.cc anadns.hh \
	logger.cc statbag.cc  dnspcap.cc dnspcap.hh dnsparser.cc dnsrecords.cc dnsparser.hh 

dnsreplay_LDFLAGS= @THREADFLAGS@ @DYNLINKFLAGS@ 


dnsscope_SOURCES=dnsscope.cc misc.cc unix_utility.cc qtype.cc \
	logger.cc statbag.cc  dnspcap.cc dnspcap.hh dnsparser.cc dnsrecords.cc

dnsscope_LDFLAGS= @THREADFLAGS@ @DYNLINKFLAGS@ 


# INCLUDES=-I/usr/include/mysql

pdns_recursor_SOURCES=syncres.cc resolver.hh misc.cc unix_utility.cc qtype.cc \
logger.cc statbag.cc dnspacket.cc arguments.cc  lwres.cc pdns_recursor.cc lwres.hh \
mtasker.hh sillyrecords.cc syncres.hh recursor_cache.cc recursor_cache.hh 

#../modules/gmysqlbackend/smysql.cc 

pdns_recursor_LDFLAGS=
pdns_recursor_LDADD=

pdns_control_SOURCES=dynloader.cc dynmessenger.cc  arguments.cc logger.cc statbag.cc misc.cc unix_utility.cc
pdns_control_INCLUDES=path.hh
pdns_control_LDFLAGS=@THREADFLAGS@

# binpatch_SOURCES=binpatch.cc 

SUBDIRS= backends .

