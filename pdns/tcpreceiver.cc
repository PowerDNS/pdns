/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2012  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include "packetcache.hh"
#include "utility.hh"
#include "dnssecinfra.hh"
#include "dnsseckeeper.hh"
#include <cstdio>
#include "base32.hh"
#include <cstring>
#include <cstdlib>
#include <sys/types.h>
#include <iostream>
#include <string>
#include "tcpreceiver.hh"
#include "sstuff.hh"
#include <boost/foreach.hpp>
#include <errno.h>
#include <signal.h>
#include "base64.hh"
#include "ueberbackend.hh"
#include "dnspacket.hh"
#include "nameserver.hh"
#include "distributor.hh"
#include "lock.hh"
#include "logger.hh"
#include "arguments.hh"

#include "packethandler.hh"
#include "statbag.hh"
#include "resolver.hh"
#include "communicator.hh"
#include "namespaces.hh"
#include "signingpipe.hh"
extern PacketCache PC;
extern StatBag S;

/**
\file tcpreceiver.cc
\brief This file implements the tcpreceiver that receives and answers questions over TCP/IP
*/

pthread_mutex_t TCPNameserver::s_plock = PTHREAD_MUTEX_INITIALIZER;
Semaphore *TCPNameserver::d_connectionroom_sem;
PacketHandler *TCPNameserver::s_P; 
int TCPNameserver::s_timeout;
NetmaskGroup TCPNameserver::d_ng;

void TCPNameserver::go()
{
  L<<Logger::Error<<"Creating backend connection for TCP"<<endl;
  s_P=0;
  try {
    s_P=new PacketHandler;
  }
  catch(AhuException &ae) {
    L<<Logger::Error<<Logger::NTLog<<"TCP server is unable to launch backends - will try again when questions come in"<<endl;
    L<<Logger::Error<<"TCP server is unable to launch backends - will try again when questions come in: "<<ae.reason<<endl;
  }
  pthread_create(&d_tid, 0, launcher, static_cast<void *>(this));
}

void *TCPNameserver::launcher(void *data)
{
  static_cast<TCPNameserver *>(data)->thread();
  return 0;
}

// throws AhuException if things didn't go according to plan, returns 0 if really 0 bytes were read
int readnWithTimeout(int fd, void* buffer, unsigned int n, bool throwOnEOF=true)
{
  unsigned int bytes=n;
  char *ptr = (char*)buffer;
  int ret;
  while(bytes) {
    ret=read(fd, ptr, bytes);
    if(ret < 0) {
      if(errno==EAGAIN) {
        ret=waitForData(fd, 5);
        if(ret < 0)
          throw NetworkError("Waiting for data read");
        if(!ret)
          throw NetworkError("Timeout reading data");
        continue;
      }
      else
        throw NetworkError("Reading data: "+stringerror());
    }
    if(!ret) {
      if(!throwOnEOF && n == bytes)
        return 0;
      else
        throw NetworkError("Did not fulfill read from TCP due to EOF");
    }
    
    ptr += ret;
    bytes -= ret;
  }
  return n;
}

// ditto
void writenWithTimeout(int fd, const void *buffer, unsigned int n)
{
  unsigned int bytes=n;
  const char *ptr = (char*)buffer;
  int ret;
  while(bytes) {
    ret=write(fd, ptr, bytes);
    if(ret < 0) {
      if(errno==EAGAIN) {
        ret=waitForRWData(fd, false, 5, 0);
        if(ret < 0)
          throw NetworkError("Waiting for data write");
        if(!ret)
          throw NetworkError("Timeout writing data");
        continue;
      }
      else
        throw NetworkError("Writing data: "+stringerror());
    }
    if(!ret) {
      throw NetworkError("Did not fulfill TCP write due to EOF");
    }
    
    ptr += ret;
    bytes -= ret;
  }
}

void connectWithTimeout(int fd, struct sockaddr* remote, size_t socklen)
{
  int err;
  Utility::socklen_t len=sizeof(err);

#ifndef WIN32
  if((err=connect(fd, remote, socklen))<0 && errno!=EINPROGRESS) 
#else
  if((err=connect(clisock, remote, socklen))<0 && WSAGetLastError() != WSAEWOULDBLOCK ) 
#endif // WIN32
    throw NetworkError("connect: "+stringerror());

  if(!err)
    goto done;
  
  err=waitForRWData(fd, false, 5, 0);
  if(err == 0)
    throw NetworkError("Timeout connecting to remote");
  if(err < 0)
    throw NetworkError("Error connecting to remote");

  if(getsockopt(fd, SOL_SOCKET,SO_ERROR,(char *)&err,&len)<0)
    throw NetworkError("Error connecting to remote: "+stringerror()); // Solaris

  if(err)
    throw NetworkError("Error connecting to remote: "+string(strerror(err)));

 done:
  ;
}

void TCPNameserver::sendPacket(shared_ptr<DNSPacket> p, int outsock)
{
  uint16_t len=htons(p->getString().length());
  string buffer((const char*)&len, 2);
  buffer.append(p->getString());
  writenWithTimeout(outsock, buffer.c_str(), buffer.length());
}


void TCPNameserver::getQuestion(int fd, char *mesg, int pktlen, const ComboAddress &remote)
try
{
  readnWithTimeout(fd, mesg, pktlen);
}
catch(NetworkError& ae) {
  throw NetworkError("Error reading DNS data from TCP client "+remote.toString()+": "+ae.what());
}

static void proxyQuestion(shared_ptr<DNSPacket> packet)
{
  int sock=socket(AF_INET, SOCK_STREAM, 0);
  
  Utility::setCloseOnExec(sock);
  if(sock < 0)
    throw NetworkError("Error making TCP connection socket to recursor: "+stringerror());

  Utility::setNonBlocking(sock);
  ServiceTuple st;
  st.port=53;
  parseService(::arg()["recursor"],st);

  try {
    ComboAddress recursor(st.host, st.port);
    connectWithTimeout(sock, (struct sockaddr*)&recursor, recursor.getSocklen());
    const string &buffer=packet->getString();
    
    uint16_t len=htons(buffer.length()), slen;
    
    writenWithTimeout(sock, &len, 2);
    writenWithTimeout(sock, buffer.c_str(), buffer.length());
    
    readnWithTimeout(sock, &len, 2);
    len=ntohs(len);

    char answer[len];
    readnWithTimeout(sock, answer, len);

    slen=htons(len);
    writenWithTimeout(packet->getSocket(), &slen, 2);
    
    writenWithTimeout(packet->getSocket(), answer, len);
  }
  catch(NetworkError& ae) {
    close(sock);
    throw NetworkError("While proxying a question to recursor "+st.host+": " +ae.what());
  }
  close(sock);
  return;
}

void *TCPNameserver::doConnection(void *data)
{
  shared_ptr<DNSPacket> packet;
  // Fix gcc-4.0 error (on AMD64)
  int fd=(int)(long)data; // gotta love C (generates a harmless warning on opteron)
  pthread_detach(pthread_self());
  Utility::setNonBlocking(fd);
  try {
    char mesg[512];
    
    DLOG(L<<"TCP Connection accepted on fd "<<fd<<endl);
    bool logDNSQueries= ::arg().mustDo("log-dns-queries");
    for(;;) {
      ComboAddress remote;
      socklen_t remotelen=sizeof(remote);
      if(getpeername(fd, (struct sockaddr *)&remote, &remotelen) < 0) {
        L<<Logger::Error<<"Received question from socket which had no remote address, dropping ("<<stringerror()<<")"<<endl;
        break;
      }

      uint16_t pktlen;
      if(!readnWithTimeout(fd, &pktlen, 2, false))
        break;
      else
        pktlen=ntohs(pktlen);

      if(pktlen>511) {
        L<<Logger::Error<<"Received an overly large question from "<<remote.toString()<<", dropping"<<endl;
        break;
      }
      
      getQuestion(fd, mesg, pktlen, remote);
      S.inc("tcp-queries");      

      packet=shared_ptr<DNSPacket>(new DNSPacket);
      packet->setRemote(&remote);
      packet->d_tcp=true;
      packet->setSocket(fd);
      if(packet->parse(mesg, pktlen)<0)
        break;
      
      if(packet->qtype.getCode()==QType::AXFR || packet->qtype.getCode()==QType::IXFR ) {
        if(doAXFR(packet->qdomain, packet, fd)) 
          S.inc("tcp-answers");  
        continue;
      }

      shared_ptr<DNSPacket> reply; 
      shared_ptr<DNSPacket> cached= shared_ptr<DNSPacket>(new DNSPacket);
      if(logDNSQueries)  {
        string remote;
        if(packet->hasEDNSSubnet()) 
          remote = packet->getRemote() + "<-" + packet->getRealRemote().toString();
        else
          remote = packet->getRemote();
        L << Logger::Notice<<"TCP Remote "<< remote <<" wants '" << packet->qdomain<<"|"<<packet->qtype.getName() << 
        "', do = " <<packet->d_dnssecOk <<", bufsize = "<< packet->getMaxReplyLen()<<": ";
      }


      if(!packet->d.rd && packet->couldBeCached() && PC.get(packet.get(), cached.get())) { // short circuit - does the PacketCache recognize this question?
        if(logDNSQueries)
          L<<"packetcache HIT"<<endl;
        cached->setRemote(&packet->d_remote);
        cached->d.id=packet->d.id;
        cached->d.rd=packet->d.rd; // copy in recursion desired bit 
        cached->commitD(); // commit d to the packet                        inlined

        sendPacket(cached, fd); // presigned, don't do it again
        S.inc("tcp-answers");
        continue;
      }
      if(logDNSQueries)
          L<<"packetcache MISS"<<endl;  
      {
        Lock l(&s_plock);
        if(!s_P) {
          L<<Logger::Error<<"TCP server is without backend connections, launching"<<endl;
          s_P=new PacketHandler;
        }
        bool shouldRecurse;

        reply=shared_ptr<DNSPacket>(s_P->questionOrRecurse(packet.get(), &shouldRecurse)); // we really need to ask the backend :-)

        if(shouldRecurse) {
          proxyQuestion(packet);
          continue;
        }
      }

      if(!reply)  // unable to write an answer?
        break;
        
      S.inc("tcp-answers");
      sendPacket(reply, fd);
    }
  }
  catch(DBException &e) {
    Lock l(&s_plock);
    delete s_P;
    s_P = 0;

    L<<Logger::Error<<"TCP Connection Thread unable to answer a question because of a backend error, cycling"<<endl;
  }
  catch(AhuException &ae) {
    Lock l(&s_plock);
    delete s_P;
    s_P = 0; // on next call, backend will be recycled
    L<<Logger::Error<<"TCP nameserver had error, cycling backend: "<<ae.reason<<endl;
  }
  catch(NetworkError &e) {
    L<<Logger::Info<<"TCP Connection Thread died because of network error: "<<e.what()<<endl;
  }

  catch(std::exception &e) {
    L<<Logger::Error<<"TCP Connection Thread died because of STL error: "<<e.what()<<endl;
  }
  catch( ... )
  {
    L << Logger::Error << "TCP Connection Thread caught unknown exception." << endl;
  }
  d_connectionroom_sem->post();
  Utility::closesocket(fd);

  return 0;
}


// call this method with s_plock held!
bool TCPNameserver::canDoAXFR(shared_ptr<DNSPacket> q)
{
  if(::arg().mustDo("disable-axfr"))
    return false;

  if(q->d_havetsig) { // if you have one, it must be good
    TSIGRecordContent trc;
    string keyname, secret;
    if(!checkForCorrectTSIG(q.get(), s_P->getBackend(), &keyname, &secret, &trc))
      return false;
    
    DNSSECKeeper dk;
    
    if(!dk.TSIGGrantsAccess(q->qdomain, keyname, trc.d_algoName)) {
      L<<Logger::Error<<"AXFR '"<<q->qdomain<<"' denied: key with name '"<<keyname<<"' and algorithm '"<<trc.d_algoName<<"' does not grant access to zone"<<endl;
      return false;
    }
    else {
      L<<Logger::Warning<<"AXFR of domain '"<<q->qdomain<<"' allowed: TSIG signed request with authorized key '"<<keyname<<"' and algorithm '"<<trc.d_algoName<<"'"<<endl;
      return true;
    }
  }
  
  // cerr<<"checking allow-axfr-ips"<<endl;
  if(!(::arg()["allow-axfr-ips"].empty()) && d_ng.match( (ComboAddress *) &q->d_remote )) {
    L<<Logger::Warning<<"AXFR of domain '"<<q->qdomain<<"' allowed: client IP "<<q->getRemote()<<" is in allow-axfr-ips"<<endl;
    return true;
  }

  FindNS fns;

  // cerr<<"doing per-zone-axfr-acls"<<endl;
  SOAData sd;
  sd.db=(DNSBackend *)-1;
  if(s_P->getBackend()->getSOA(q->qdomain,sd)) {
    // cerr<<"got backend and SOA"<<endl;
    DNSBackend *B=sd.db;
    vector<string> acl;
    B->getDomainMetadata(q->qdomain, "ALLOW-AXFR-FROM", acl);
    for (vector<string>::const_iterator i = acl.begin(); i != acl.end(); ++i) {
      // cerr<<"matching against "<<*i<<endl;
      if(pdns_iequals(*i, "AUTO-NS")) {
        // cerr<<"AUTO-NS magic please!"<<endl;

        DNSResourceRecord rr;
        set<string> nsset;

        B->lookup(QType(QType::NS),q->qdomain);
        while(B->get(rr)) 
          nsset.insert(rr.content);
        for(set<string>::const_iterator j=nsset.begin();j!=nsset.end();++j) {
          vector<string> nsips=fns.lookup(*j, B);
          for(vector<string>::const_iterator k=nsips.begin();k!=nsips.end();++k) {
            // cerr<<"got "<<*k<<" from AUTO-NS"<<endl;
            if(*k == q->getRemote())
            {
              // cerr<<"got AUTO-NS hit"<<endl;
              L<<Logger::Warning<<"AXFR of domain '"<<q->qdomain<<"' allowed: client IP "<<q->getRemote()<<" is in NSset"<<endl;
              return true;
            }
          }
        }
      }
      else
      {
        Netmask nm = Netmask(*i);
        if(nm.match( (ComboAddress *) &q->d_remote ))
        {
          L<<Logger::Warning<<"AXFR of domain '"<<q->qdomain<<"' allowed: client IP "<<q->getRemote()<<" is in per-domain ACL"<<endl;
          // cerr<<"hit!"<<endl;
          return true;
        }
      }
    }
  }  

  extern CommunicatorClass Communicator;

  if(Communicator.justNotified(q->qdomain, q->getRemote())) { // we just notified this ip 
    L<<Logger::Warning<<"Approved AXFR of '"<<q->qdomain<<"' from recently notified slave "<<q->getRemote()<<endl;
    return true;
  }

  L<<Logger::Error<<"AXFR of domain '"<<q->qdomain<<"' denied: client IP "<<q->getRemote()<<" has no permission"<<endl;
  return false;
}

namespace {
  struct NSECXEntry
  {
    set<uint16_t> d_set;
    unsigned int d_ttl;
  };

  DNSResourceRecord makeDNSRRFromSOAData(const SOAData& sd)
  {
    DNSResourceRecord soa;
    soa.qname= sd.qname;
    soa.qtype=QType::SOA;
    soa.content=serializeSOAData(sd);
    soa.ttl=sd.ttl;
    soa.domain_id=sd.domain_id;
    soa.auth = true;
    soa.d_place=DNSResourceRecord::ANSWER;
    return soa;
  }

  shared_ptr<DNSPacket> getFreshAXFRPacket(shared_ptr<DNSPacket> q)
  {
    shared_ptr<DNSPacket> ret = shared_ptr<DNSPacket>(q->replyPacket());
    ret->setCompress(false);
    ret->d_dnssecOk=false; // RFC 5936, 2.2.5
    ret->d_tcp = true;
    return ret;
  }
}


/** do the actual zone transfer. Return 0 in case of error, 1 in case of success */
int TCPNameserver::doAXFR(const string &target, shared_ptr<DNSPacket> q, int outsock)
{
  bool noAXFRBecauseOfNSEC3Narrow=false;
  NSEC3PARAMRecordContent ns3pr;
  bool narrow;
  bool NSEC3Zone=false;
  
  DNSSECKeeper dk;
  dk.clearCaches(target);
  bool securedZone = dk.isSecuredZone(target);
  if(dk.getNSEC3PARAM(target, &ns3pr, &narrow)) {
    NSEC3Zone=true;
    if(narrow) {
      L<<Logger::Error<<"Not doing AXFR of an NSEC3 narrow zone.."<<endl;
      noAXFRBecauseOfNSEC3Narrow=true;
    }
  }

  shared_ptr<DNSPacket> outpacket= getFreshAXFRPacket(q);
  if(q->d_dnssecOk)
    outpacket->d_dnssecOk=true; // RFC 5936, 2.2.5 'SHOULD'
  
  if(noAXFRBecauseOfNSEC3Narrow) {
    L<<Logger::Error<<"AXFR of domain '"<<target<<"' denied to "<<q->getRemote()<<endl;
    outpacket->setRcode(RCode::Refused); 
    // FIXME: should actually figure out if we are auth over a zone, and send out 9 if we aren't
    sendPacket(outpacket,outsock);
    return 0;
  }
  
  L<<Logger::Error<<"AXFR of domain '"<<target<<"' initiated by "<<q->getRemote()<<endl;

  SOAData sd;
  sd.db=(DNSBackend *)-1; // force uncached answer
  {
    Lock l(&s_plock);
    DLOG(L<<"Looking for SOA"<<endl);    // find domain_id via SOA and list complete domain. No SOA, no AXFR
    if(!s_P) {
      L<<Logger::Error<<"TCP server is without backend connections in doAXFR, launching"<<endl;
      s_P=new PacketHandler;
    }

    if(!s_P->getBackend()->getSOA(target, sd) || !canDoAXFR(q)) {
      L<<Logger::Error<<"AXFR of domain '"<<target<<"' failed: not authoritative"<<endl;
      outpacket->setRcode(9); // 'NOTAUTH'
      sendPacket(outpacket,outsock);
      return 0;
    }
  }
 
  UeberBackend db;
  sd.db=(DNSBackend *)-1; // force uncached answer
  if(!db.getSOA(target, sd)) {
    L<<Logger::Error<<"AXFR of domain '"<<target<<"' failed: not authoritative in second instance"<<endl;
    outpacket->setRcode(9); // 'NOTAUTH'
    sendPacket(outpacket,outsock);
    return 0;
  }

  if(!sd.db || sd.db==(DNSBackend *)-1) {
    L<<Logger::Error<<"Error determining backend for domain '"<<target<<"' trying to serve an AXFR"<<endl;
    outpacket->setRcode(RCode::ServFail);
    sendPacket(outpacket,outsock);
    return 0;
  }

  TSIGRecordContent trc;
  string tsigkeyname, tsigsecret;

  q->getTSIGDetails(&trc, &tsigkeyname, 0);

  if(!tsigkeyname.empty()) {
    string tsig64, algorithm;
    Lock l(&s_plock);
    s_P->getBackend()->getTSIGKey(tsigkeyname, &algorithm, &tsig64);
    B64Decode(tsig64, tsigsecret);
  }
  
  
  UeberBackend signatureDB; 
  
  // SOA *must* go out first, our signing pipe might reorder
  DLOG(L<<"Sending out SOA"<<endl);
  DNSResourceRecord soa = makeDNSRRFromSOAData(sd);
  outpacket->addRecord(soa);
  editSOA(dk, sd.qname, outpacket.get());
  if(securedZone) {
    set<string, CIStringCompare> authSet;
    authSet.insert(target);
    addRRSigs(dk, signatureDB, authSet, outpacket->getRRS());
  }
  
  if(!tsigkeyname.empty())
    outpacket->setTSIGDetails(trc, tsigkeyname, tsigsecret, trc.d_mac); // first answer is 'normal'
  
  sendPacket(outpacket, outsock);
  
  trc.d_mac = outpacket->d_trc.d_mac;
  outpacket = getFreshAXFRPacket(q);
  
  ChunkedSigningPipe csp(target, securedZone, "", ::arg().asNum("signing-threads"));
  
  typedef map<string, NSECXEntry> nsecxrepo_t;
  nsecxrepo_t nsecxrepo;
  
  // this is where the DNSKEYs go  in
  
  DNSSECKeeper::keyset_t keys = dk.getKeys(target);
  
  DNSResourceRecord rr;
  
  rr.qname = target;
  rr.ttl = sd.default_ttl;
  rr.auth = 1; // please sign!

  BOOST_FOREACH(const DNSSECKeeper::keyset_t::value_type& value, keys) {
    rr.qtype = QType(QType::DNSKEY);
    rr.content = value.first.getDNSKEY().getZoneRepresentation();
    string keyname = NSEC3Zone ? hashQNameWithSalt(ns3pr.d_iterations, ns3pr.d_salt, rr.qname) : labelReverse(rr.qname);
    NSECXEntry& ne = nsecxrepo[keyname];
    
    ne.d_set.insert(rr.qtype.getCode());
    ne.d_ttl = sd.default_ttl;
    csp.submit(rr);
  }
  
  if(::arg().mustDo("direct-dnskey")) {
    sd.db->lookup(QType(QType::DNSKEY), target, NULL, sd.domain_id);
    while(sd.db->get(rr)) {
      rr.ttl = sd.default_ttl;
      csp.submit(rr);
    }
  }

  if(NSEC3Zone) { // now stuff in the NSEC3PARAM
    rr.qtype = QType(QType::NSEC3PARAM);
    ns3pr.d_flags = 0;
    rr.content = ns3pr.getZoneRepresentation();
    ns3pr.d_flags = 1;
    string keyname = hashQNameWithSalt(ns3pr.d_iterations, ns3pr.d_salt, rr.qname);
    NSECXEntry& ne = nsecxrepo[keyname];
    
    ne.d_set.insert(rr.qtype.getCode());
    csp.submit(rr);
  }
  
  // now start list zone
  if(!(sd.db->list(target, sd.domain_id))) {  
    L<<Logger::Error<<"Backend signals error condition"<<endl;
    outpacket->setRcode(2); // 'SERVFAIL'
    sendPacket(outpacket,outsock);
    return 0;
  }

  /* now write all other records */
  
  string keyname;
  DTime dt;
  dt.set();
  int records=0;
  while(sd.db->get(rr)) {
    if (rr.qtype.getCode() == QType::RRSIG)
      continue;

    // only skip the DNSKEY if direct-dnskey is enabled, to avoid changing behaviour
    // when it is not enabled.
    if(::arg().mustDo("direct-dnskey") && rr.qtype.getCode() == QType::DNSKEY)
      continue;

    records++;
    if(securedZone && (rr.auth || (!NSEC3Zone && rr.qtype.getCode() == QType::NS) || rr.qtype.getCode() == QType::DS)) { // this is probably NSEC specific, NSEC3 is different
      if (NSEC3Zone || rr.qtype.getCode()) {
        keyname = NSEC3Zone ? hashQNameWithSalt(ns3pr.d_iterations, ns3pr.d_salt, rr.qname) : labelReverse(rr.qname);
        NSECXEntry& ne = nsecxrepo[keyname];
        ne.d_ttl = sd.default_ttl;
        if (rr.qtype.getCode()) {
          ne.d_set.insert(rr.qtype.getCode());
        }
      }
    }

    if (!rr.qtype.getCode())
      continue; // skip empty non-terminals

    if(rr.qtype.getCode() == QType::SOA)
      continue; // skip SOA - would indicate end of AXFR

    if(csp.submit(rr)) {
      for(;;) {
        outpacket->getRRS() = csp.getChunk();
        if(!outpacket->getRRS().empty()) {
          if(!tsigkeyname.empty()) 
            outpacket->setTSIGDetails(trc, tsigkeyname, tsigsecret, trc.d_mac, true);
          sendPacket(outpacket, outsock);
          trc.d_mac=outpacket->d_trc.d_mac;
          outpacket=getFreshAXFRPacket(q);
        }
        else
          break;
      }
    }
  }
  unsigned int udiff=dt.udiffNoReset();
  /*
  cerr<<"Starting NSEC: "<<csp.d_signed/(udiff/1000000.0)<<" sigs/s, "<<csp.d_signed<<" / "<<udiff/1000000.0<<endl;
  cerr<<"Outstanding: "<<csp.d_outstanding<<", "<<csp.d_queued - csp.d_signed << endl;
  cerr<<"Ready for consumption: "<<csp.getReady()<<endl;
  */
  if(securedZone) {   
    if(NSEC3Zone) {
      for(nsecxrepo_t::const_iterator iter = nsecxrepo.begin(); iter != nsecxrepo.end(); ++iter) {
        NSEC3RecordContent n3rc;
        n3rc.d_set = iter->second.d_set;
        if (n3rc.d_set.size())
          n3rc.d_set.insert(QType::RRSIG);
        n3rc.d_salt=ns3pr.d_salt;
        n3rc.d_flags = ns3pr.d_flags;
        n3rc.d_iterations = ns3pr.d_iterations;
        n3rc.d_algorithm = 1; // SHA1, fixed in PowerDNS for now
        if(boost::next(iter) != nsecxrepo.end()) {
          n3rc.d_nexthash = boost::next(iter)->first;
        }
        else
          n3rc.d_nexthash=nsecxrepo.begin()->first;
    
        rr.qname = dotConcat(toLower(toBase32Hex(iter->first)), sd.qname);
    
        rr.ttl = sd.default_ttl;
        rr.content = n3rc.getZoneRepresentation();
        rr.qtype = QType::NSEC3;
        rr.d_place = DNSResourceRecord::ANSWER;
        rr.auth=true;
        if(csp.submit(rr)) {
          for(;;) {
            outpacket->getRRS() = csp.getChunk();
            if(!outpacket->getRRS().empty()) {
              if(!tsigkeyname.empty())
                outpacket->setTSIGDetails(trc, tsigkeyname, tsigsecret, trc.d_mac, true);
              sendPacket(outpacket, outsock);
              trc.d_mac=outpacket->d_trc.d_mac;
              outpacket=getFreshAXFRPacket(q);
            }
            else
              break;
          }
        }
      }
    }
    else for(nsecxrepo_t::const_iterator iter = nsecxrepo.begin(); iter != nsecxrepo.end(); ++iter) {
      NSECRecordContent nrc;
      nrc.d_set = iter->second.d_set;
      nrc.d_set.insert(QType::RRSIG);
      nrc.d_set.insert(QType::NSEC);
      if(boost::next(iter) != nsecxrepo.end()) {
        nrc.d_next = labelReverse(boost::next(iter)->first);
      }
      else
        nrc.d_next=labelReverse(nsecxrepo.begin()->first);
  
      rr.qname = labelReverse(iter->first);
  
      rr.ttl = sd.default_ttl;
      rr.content = nrc.getZoneRepresentation();
      rr.qtype = QType::NSEC;
      rr.d_place = DNSResourceRecord::ANSWER;
      rr.auth=true;
      if(csp.submit(rr)) {
        for(;;) {
          outpacket->getRRS() = csp.getChunk();
          if(!outpacket->getRRS().empty()) {
            if(!tsigkeyname.empty())
              outpacket->setTSIGDetails(trc, tsigkeyname, tsigsecret, trc.d_mac, true); 
            sendPacket(outpacket, outsock);
            trc.d_mac=outpacket->d_trc.d_mac;
            outpacket=getFreshAXFRPacket(q);
          }
          else
            break;
        }
      }
    }
  }
  udiff=dt.udiffNoReset();
  /*
  cerr<<"Flushing pipe: "<<csp.d_signed/(udiff/1000000.0)<<" sigs/s, "<<csp.d_signed<<" / "<<udiff/1000000.0<<endl;
  cerr<<"Outstanding: "<<csp.d_outstanding<<", "<<csp.d_queued - csp.d_signed << endl;
  cerr<<"Ready for consumption: "<<csp.getReady()<<endl;
  * */
  for(;;) { 
    outpacket->getRRS() = csp.getChunk(true); // flush the pipe
    if(!outpacket->getRRS().empty()) {
      if(!tsigkeyname.empty())
        outpacket->setTSIGDetails(trc, tsigkeyname, tsigsecret, trc.d_mac, true); // first answer is 'normal'
      sendPacket(outpacket, outsock);
      trc.d_mac=outpacket->d_trc.d_mac;
      outpacket=getFreshAXFRPacket(q);
    }
    else 
      break;
  }
  
  udiff=dt.udiffNoReset();
  if(securedZone) 
    L<<Logger::Info<<"Done signing: "<<csp.d_signed/(udiff/1000000.0)<<" sigs/s, "<<endl;
  
  DLOG(L<<"Done writing out records"<<endl);
  /* and terminate with yet again the SOA record */
  outpacket=getFreshAXFRPacket(q);
  outpacket->addRecord(soa);
  editSOA(dk, sd.qname, outpacket.get());
  if(!tsigkeyname.empty())
    outpacket->setTSIGDetails(trc, tsigkeyname, tsigsecret, trc.d_mac, true); 
  
  sendPacket(outpacket, outsock);
  
  DLOG(L<<"last packet - close"<<endl);
  L<<Logger::Error<<"AXFR of domain '"<<target<<"' to "<<q->getRemote()<<" finished"<<endl;

  return 1;
}

TCPNameserver::~TCPNameserver()
{
  delete d_connectionroom_sem;
}

TCPNameserver::TCPNameserver()
{
//  sem_init(&d_connectionroom_sem,0,::arg().asNum("max-tcp-connections"));
  d_connectionroom_sem = new Semaphore( ::arg().asNum( "max-tcp-connections" ));

  s_timeout=10;
  vector<string>locals;
  stringtok(locals,::arg()["local-address"]," ,");

  vector<string>locals6;
  stringtok(locals6,::arg()["local-ipv6"]," ,");

  if(locals.empty() && locals6.empty())
    throw AhuException("No local address specified");

  d_highfd=0;

  vector<string> parts;
  stringtok( parts, ::arg()["allow-axfr-ips"], ", \t" ); // is this IP on the guestlist?
  for( vector<string>::const_iterator i = parts.begin(); i != parts.end(); ++i ) {
    d_ng.addMask( *i );
  }

#ifndef WIN32
  signal(SIGPIPE,SIG_IGN);
#endif // WIN32

  for(vector<string>::const_iterator laddr=locals.begin();laddr!=locals.end();++laddr) {
    int s=socket(AF_INET,SOCK_STREAM,0); 
    Utility::setCloseOnExec(s);
    
    if(s<0) 
      throw AhuException("Unable to acquire TCP socket: "+stringerror());

    ComboAddress local(*laddr, ::arg().asNum("local-port"));
      
    int tmp=1;
    if(setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(char*)&tmp,sizeof tmp)<0) {
      L<<Logger::Error<<"Setsockopt failed"<<endl;
      exit(1);  
    }
    
    if(::bind(s, (sockaddr*)&local, local.getSocklen())<0) {
      L<<Logger::Error<<"binding to TCP socket: "<<strerror(errno)<<endl;
      throw AhuException("Unable to bind to TCP socket");
    }
    
    listen(s,128);
    L<<Logger::Error<<"TCP server bound to "<<local.toStringWithPort()<<endl;
    d_sockets.push_back(s);
    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = s;
    pfd.events = POLLIN;

    d_prfds.push_back(pfd);

    d_highfd=max(s,d_highfd);
  }

#if !WIN32 && HAVE_IPV6
  for(vector<string>::const_iterator laddr=locals6.begin();laddr!=locals6.end();++laddr) {
    int s=socket(AF_INET6,SOCK_STREAM,0); 
    Utility::setCloseOnExec(s);

    if(s<0) 
      throw AhuException("Unable to acquire TCPv6 socket: "+stringerror());

    ComboAddress local(*laddr, ::arg().asNum("local-port"));

    int tmp=1;
    if(setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(char*)&tmp,sizeof tmp)<0) {
      L<<Logger::Error<<"Setsockopt failed"<<endl;
      exit(1);  
    }
    if(setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &tmp, sizeof(tmp)) < 0) {
      L<<Logger::Error<<"Failed to set IPv6 socket to IPv6 only, continuing anyhow: "<<strerror(errno)<<endl;
    }
    if(bind(s, (const sockaddr*)&local, local.getSocklen())<0) {
      L<<Logger::Error<<"binding to TCP socket: "<<strerror(errno)<<endl;
      throw AhuException("Unable to bind to TCPv6 socket");
    }
    
    listen(s,128);
    L<<Logger::Error<<"TCPv6 server bound to "<<local.toStringWithPort()<<endl; // this gets %eth0 right
    d_sockets.push_back(s);

    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = s;
    pfd.events = POLLIN;

    d_prfds.push_back(pfd);
    d_highfd=max(s, d_highfd);
  }
#endif // WIN32
}


//! Start of TCP operations thread, we launch a new thread for each incoming TCP question
void TCPNameserver::thread()
{
  try {
    for(;;) {
      int fd;
      struct sockaddr_in remote;
      Utility::socklen_t addrlen=sizeof(remote);

      int ret=poll(&d_prfds[0], d_prfds.size(), -1); // blocks, forever if need be
      if(ret <= 0)
        continue;

      int sock=-1;
      BOOST_FOREACH(const struct pollfd& pfd, d_prfds) {
        if(pfd.revents == POLLIN) {
          sock = pfd.fd;
          addrlen=sizeof(remote);

          if((fd=accept(sock, (sockaddr*)&remote, &addrlen))<0) {
            L<<Logger::Error<<"TCP question accept error: "<<strerror(errno)<<endl;
            
            if(errno==EMFILE) {
              L<<Logger::Error<<Logger::NTLog<<"TCP handler out of filedescriptors, exiting, won't recover from this"<<endl;
              exit(1);
            }
          }
          else {
            pthread_t tid;
            d_connectionroom_sem->wait(); // blocks if no connections are available

            int room;
            d_connectionroom_sem->getValue( &room);
            if(room<1)
              L<<Logger::Warning<<Logger::NTLog<<"Limit of simultaneous TCP connections reached - raise max-tcp-connections"<<endl;

            if(pthread_create(&tid, 0, &doConnection, (void *)fd)) {
              L<<Logger::Error<<"Error creating thread: "<<stringerror()<<endl;
              d_connectionroom_sem->post();
            }
          }
        }
      }
    }
  }
  catch(AhuException &AE) {
    L<<Logger::Error<<"TCP Nameserver thread dying because of fatal error: "<<AE.reason<<endl;
  }
  catch(...) {
    L<<Logger::Error<<"TCPNameserver dying because of an unexpected fatal error"<<endl;
  }
  exit(1); // take rest of server with us
}


