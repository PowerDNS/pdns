AM_CXXFLAGS=-DSYSCONFDIR=\"@sysconfdir@\" -DLIBDIR=\"@libdir@\" -DLOCALSTATEDIR=\"@socketdir@\" -Ibackends/bind 
AM_CPPFLAGS=-Ibackends/bind @THREADFLAGS@

EXTRA_DIST = docs/Makefile \
docs/gslb-operations.sgml docs/powerdns-case.sgml docs/powerdns-install.sgml \
docs/powerdns-overview.sgml docs/powerdns-technical.sgml  \
 release-scripts/ docs/pdns.sgml mtasker.cc \
docs/pdns_control.8  docs/pdns_server.8 docs/zone2sql.8

noinst_SCRIPTS = pdns
sysconf_DATA = pdns.conf-dist 

if RECURSOR
bin_PROGRAMS = pdns_control syncres
else
bin_PROGRAMS = pdns_control 
endif

sbin_PROGRAMS = pdns_server 

EXTRA_PROGRAMS=syncres pdns_control

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
backends/bind/huffman.cc backends/gsql/gsqlbackend.cc \
backends/gsql/gsqlbackend.hh backends/gsql/ssql.hh \
sillyrecords.cc recbcomm.hh recbcomm.cc

#
pdns_server_LDFLAGS= @moduleobjects@ @modulelibs@ @DYNLINKFLAGS@ @LIBDL@ @THREADFLAGS@
pdns_server_INCLUDES=


#resolver_SOURCES=resolver.cc resolver.hh misc.cc unix_utility.cc qtype.cc \
#logger.cc statbag.cc dnspacket.cc arguments.cc  tres.cc

syncres_SOURCES=syncres.cc resolver.hh misc.cc unix_utility.cc qtype.cc \
logger.cc statbag.cc dnspacket.cc arguments.cc  lwres.cc recns.cc lwres.hh \
mtasker.hh sillyrecords.cc

syncres_LDFLAGS=
syncres_LDADD=

pdns_control_SOURCES=dynloader.cc dynmessenger.cc  arguments.cc logger.cc statbag.cc misc.cc unix_utility.cc
pdns_control_INCLUDES=path.hh
pdns_control_LDFLAGS=@THREADFLAGS@

# binpatch_SOURCES=binpatch.cc 

SUBDIRS= backends .

