/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2012  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
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

#include "common_startup.hh"
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
  catch(PDNSException &ae) {
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

// throws PDNSException if things didn't go according to plan, returns 0 if really 0 bytes were read
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

  if((err=connect(fd, remote, socklen))<0 && errno!=EINPROGRESS)
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

  /* Query statistics */
  if(p->qtype.getCode()!=QType::AXFR && p->qtype.getCode()!=QType::IXFR) {
    if(p->d.aa) {
      if(p->d.rcode==RCode::NXDomain)
        S.ringAccount("nxdomain-queries",p->qdomain+"/"+p->qtype.getName());
    } else if(p->isEmpty()) {
      S.ringAccount("unauth-queries",p->qdomain+"/"+p->qtype.getName());
      S.ringAccount("remotes-unauth",p->d_remote);
    }
  }

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
    int mesgsize=65535;
    scoped_array<char> mesg(new char[mesgsize]);
    
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

      // this check will always be false *if* no one touches
      // the mesg array. pktlen can be maximum of 65535 as
      // it is 2 byte unsigned variable. In getQuestion, we 
      // write to 0 up to pktlen-1 so 65535 is just right. 

      // do not remove this check as it will catch if someone
      // decreases the mesg buffer size for some reason. 
      if(pktlen > mesgsize) {
        L<<Logger::Error<<"Received an overly large question from "<<remote.toString()<<", dropping"<<endl;
        break;
      }
      
      getQuestion(fd, mesg.get(), pktlen, remote);
      S.inc("tcp-queries");      

      packet=shared_ptr<DNSPacket>(new DNSPacket);
      packet->setRemote(&remote);
      packet->d_tcp=true;
      packet->setSocket(fd);
      if(packet->parse(mesg.get(), pktlen)<0)
        break;
      
      if(packet->qtype.getCode()==QType::AXFR) {
        if(doAXFR(packet->qdomain, packet, fd))
          S.inc("tcp-answers");
        continue;
      }

      if(packet->qtype.getCode()==QType::IXFR) {
        if(doIXFR(packet, fd))
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


      if(!packet->d.rd && packet->couldBeCached() && PC.get(packet.get(), cached.get(), false)) { // short circuit - does the PacketCache recognize this question?
        if(logDNSQueries)
          L<<"packetcache HIT"<<endl;
        cached->setRemote(&packet->d_remote);
        cached->d.id=packet->d.id;
        cached->d.rd=packet->d.rd; // copy in recursion desired bit 
        cached->commitD(); // commit d to the packet                        inlined

        if(LPE) LPE->police(&(*packet), &(*cached), true);

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

        if(LPE) LPE->police(&(*packet), &(*reply), true);

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
  catch(PDNSException &ae) {
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

    string algorithm=toLowerCanonic(trc.d_algoName);
    if (algorithm == "hmac-md5.sig-alg.reg.int")
      algorithm = "hmac-md5";
    if(!dk.TSIGGrantsAccess(q->qdomain, keyname)) {
      L<<Logger::Error<<"AXFR '"<<q->qdomain<<"' denied: key with name '"<<keyname<<"' and algorithm '"<<algorithm<<"' does not grant access to zone"<<endl;
      return false;
    }
    else {
      L<<Logger::Warning<<"AXFR of domain '"<<q->qdomain<<"' allowed: TSIG signed request with authorized key '"<<keyname<<"' and algorithm '"<<algorithm<<"'"<<endl;
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
  if(s_P->getBackend()->getSOAUncached(q->qdomain,sd)) {
    // cerr<<"got backend and SOA"<<endl;
    DNSBackend *B=sd.db;
    vector<string> acl;
    s_P->getBackend()->getDomainMetadata(q->qdomain, "ALLOW-AXFR-FROM", acl);
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
    bool d_auth;
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
  shared_ptr<DNSPacket> outpacket= getFreshAXFRPacket(q);
  if(q->d_dnssecOk)
    outpacket->d_dnssecOk=true; // RFC 5936, 2.2.5 'SHOULD'

  L<<Logger::Error<<"AXFR of domain '"<<target<<"' initiated by "<<q->getRemote()<<endl;

  // determine if zone exists and AXFR is allowed using existing backend before spawning a new backend.
  SOAData sd;
  {
    Lock l(&s_plock);
    DLOG(L<<"Looking for SOA"<<endl);    // find domain_id via SOA and list complete domain. No SOA, no AXFR
    if(!s_P) {
      L<<Logger::Error<<"TCP server is without backend connections in doAXFR, launching"<<endl;
      s_P=new PacketHandler;
    }

    if (!canDoAXFR(q)) {
      L<<Logger::Error<<"AXFR of domain '"<<target<<"' failed: "<<q->getRemote()<<" cannot request AXFR"<<endl;
      outpacket->setRcode(9); // 'NOTAUTH'
      sendPacket(outpacket,outsock);
      return 0;
    }

    // canDoAXFR does all the ACL checks, and has the if(disable-axfr) shortcut, call it first.
    if(!s_P->getBackend()->getSOAUncached(target, sd)) {
      L<<Logger::Error<<"AXFR of domain '"<<target<<"' failed: not authoritative"<<endl;
      outpacket->setRcode(9); // 'NOTAUTH'
      sendPacket(outpacket,outsock);
      return 0;
    }
  }

  UeberBackend db;
  if(!db.getSOAUncached(target, sd)) {
    L<<Logger::Error<<"AXFR of domain '"<<target<<"' failed: not authoritative in second instance"<<endl;
    outpacket->setRcode(RCode::NotAuth);
    sendPacket(outpacket,outsock);
    return 0;
  }

  DNSSECKeeper dk;
  dk.clearCaches(target);
  bool securedZone = dk.isSecuredZone(target);
  bool presignedZone = dk.isPresigned(target);

  bool noAXFRBecauseOfNSEC3Narrow=false;
  NSEC3PARAMRecordContent ns3pr;
  bool narrow;
  bool NSEC3Zone=false;
  if(dk.getNSEC3PARAM(target, &ns3pr, &narrow)) {
    NSEC3Zone=true;
    if(narrow) {
      L<<Logger::Error<<"Not doing AXFR of an NSEC3 narrow zone '"<<target<<"' for "<<q->getRemote()<<endl;
      noAXFRBecauseOfNSEC3Narrow=true;
    }
  }

  if(noAXFRBecauseOfNSEC3Narrow) {
    L<<Logger::Error<<"AXFR of domain '"<<target<<"' denied to "<<q->getRemote()<<endl;
    outpacket->setRcode(RCode::Refused);
    // FIXME: should actually figure out if we are auth over a zone, and send out 9 if we aren't
    sendPacket(outpacket,outsock);
    return 0;
  }

  TSIGRecordContent trc;
  string tsigkeyname, tsigsecret;

  q->getTSIGDetails(&trc, &tsigkeyname, 0);

  if(!tsigkeyname.empty()) {
    string tsig64;
    string algorithm=toLowerCanonic(trc.d_algoName);
    if (algorithm == "hmac-md5.sig-alg.reg.int")
      algorithm = "hmac-md5";
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
  
  ChunkedSigningPipe csp(target, securedZone, "", ::arg().asNum("signing-threads", 1));
  
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

  uint8_t flags;

  if(NSEC3Zone) { // now stuff in the NSEC3PARAM
    flags = ns3pr.d_flags;
    rr.qtype = QType(QType::NSEC3PARAM);
    ns3pr.d_flags = 0;
    rr.content = ns3pr.getZoneRepresentation();
    ns3pr.d_flags = flags;
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


  const bool rectify = !(presignedZone || ::arg().mustDo("disable-axfr-rectify"));
  set<string> qnames, nsset, terms;
  vector<DNSResourceRecord> rrs;

  while(sd.db->get(rr)) {
    if(endsOn(rr.qname, target)) {
      if (rectify) {
        if (rr.qtype.getCode()) {
          qnames.insert(rr.qname);
          if(rr.qtype.getCode() == QType::NS && !pdns_iequals(rr.qname, target))
            nsset.insert(rr.qname);
        } else {
          // remove existing ents
          continue;
        }
      }
      rrs.push_back(rr);
    } else {
      L<<Logger::Warning<<"Zone '"<<target<<"' contains out-of-zone data '"<<rr.qname<<"'|"<<rr.qtype.getName()<<"', ignoring"<<endl;
      continue;
    }
  }

  if(rectify) {
    // set auth
    BOOST_FOREACH(DNSResourceRecord &rr, rrs) {
      rr.auth=true;
      if (rr.qtype.getCode() != QType::NS || !pdns_iequals(rr.qname, target)) {
        string shorter(rr.qname);
        do {
          if (pdns_iequals(shorter, target)) // apex is always auth
            continue;
          if(nsset.count(shorter) && !(pdns_iequals(rr.qname, shorter) && rr.qtype.getCode() == QType::DS))
            rr.auth=false;
        } while(chopOff(shorter));
      } else
        continue;
    }

    if(NSEC3Zone) {
      // ents are only required for NSEC3 zones
      uint32_t maxent = ::arg().asNum("max-ent-entries");
      map<string,bool> nonterm;
      BOOST_FOREACH(DNSResourceRecord &rr, rrs) {
        string shorter(rr.qname);
        while(!pdns_iequals(shorter, target) && chopOff(shorter)) {
          if(!qnames.count(shorter)) {
            if(!(maxent)) {
              L<<Logger::Warning<<"Zone '"<<target<<"' has too many empty non terminals."<<endl;
              return 0;
            }
            if (!nonterm.count(shorter)) {
              nonterm.insert(pair<string, bool>(shorter, rr.auth));
              --maxent;
            } else if (rr.auth)
              nonterm[shorter]=true;
          }
        }
      }

      pair<string,bool> nt;
      BOOST_FOREACH(nt, nonterm) {
        DNSResourceRecord rr;
        rr.qname=nt.first;
        rr.qtype="TYPE0";
        rr.auth=(nt.second || !ns3pr.d_flags);
        rrs.push_back(rr);
      }
    }
  }


  /* now write all other records */
  
  string keyname;
  set<string> ns3rrs;
  unsigned int udiff;
  DTime dt;
  dt.set();
  int records=0;
  BOOST_FOREACH(DNSResourceRecord &rr, rrs) {
    if (rr.qtype.getCode() == QType::RRSIG) {
      RRSIGRecordContent rrc(rr.content);
      if(presignedZone && rrc.d_type == QType::NSEC3)
        ns3rrs.insert(fromBase32Hex(makeRelative(rr.qname, target)));
      continue;
    }

    // only skip the DNSKEY if direct-dnskey is enabled, to avoid changing behaviour
    // when it is not enabled.
    if(::arg().mustDo("direct-dnskey") && rr.qtype.getCode() == QType::DNSKEY)
      continue;

    records++;
    if(securedZone && (rr.auth || rr.qtype.getCode() == QType::NS)) {
      if (NSEC3Zone || rr.qtype.getCode()) {
        keyname = NSEC3Zone ? hashQNameWithSalt(ns3pr.d_iterations, ns3pr.d_salt, rr.qname) : labelReverse(rr.qname);
        NSECXEntry& ne = nsecxrepo[keyname];
        ne.d_ttl = sd.default_ttl;
        ne.d_auth = (ne.d_auth || rr.auth || (NSEC3Zone && (!ns3pr.d_flags || (presignedZone && ns3pr.d_flags))));
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
  /*
  udiff=dt.udiffNoReset();
  cerr<<"Starting NSEC: "<<csp.d_signed/(udiff/1000000.0)<<" sigs/s, "<<csp.d_signed<<" / "<<udiff/1000000.0<<endl;
  cerr<<"Outstanding: "<<csp.d_outstanding<<", "<<csp.d_queued - csp.d_signed << endl;
  cerr<<"Ready for consumption: "<<csp.getReady()<<endl;
  */
  if(securedZone) {
    if(NSEC3Zone) {
      for(nsecxrepo_t::const_iterator iter = nsecxrepo.begin(); iter != nsecxrepo.end(); ++iter) {
        if(iter->second.d_auth && (!presignedZone || !ns3pr.d_flags || ns3rrs.count(iter->first))) {
          NSEC3RecordContent n3rc;
          n3rc.d_set = iter->second.d_set;
          if (n3rc.d_set.size() && (n3rc.d_set.size() != 1 || !n3rc.d_set.count(QType::NS)))
            n3rc.d_set.insert(QType::RRSIG);
          n3rc.d_salt=ns3pr.d_salt;
          n3rc.d_flags = ns3pr.d_flags;
          n3rc.d_iterations = ns3pr.d_iterations;
          n3rc.d_algorithm = 1; // SHA1, fixed in PowerDNS for now
          nsecxrepo_t::const_iterator inext = iter;
          inext++;
          if(inext == nsecxrepo.end())
            inext = nsecxrepo.begin();
          while((!inext->second.d_auth || (presignedZone && ns3pr.d_flags && !ns3rrs.count(inext->first)))  && inext != iter)
          {
            inext++;
            if(inext == nsecxrepo.end())
              inext = nsecxrepo.begin();
          }
          n3rc.d_nexthash = inext->first;
          rr.qname = dotConcat(toBase32Hex(iter->first), sd.qname);

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
  /*
  udiff=dt.udiffNoReset();
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

int TCPNameserver::doIXFR(shared_ptr<DNSPacket> q, int outsock)
{
  shared_ptr<DNSPacket> outpacket=getFreshAXFRPacket(q);
  if(q->d_dnssecOk)
    outpacket->d_dnssecOk=true; // RFC 5936, 2.2.5 'SHOULD'

  uint32_t serial = 0;
  MOADNSParser mdp(q->getString());
  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i != mdp.d_answers.end(); ++i) {
    const DNSRecord *rr = &i->first;
    if (rr->d_type == QType::SOA && rr->d_place == DNSRecord::Nameserver) {
      vector<string>parts;
      stringtok(parts, rr->d_content->getZoneRepresentation());
      if (parts.size() >= 3) {
        serial=atoi(parts[2].c_str());
      } else {
        L<<Logger::Error<<"No serial in IXFR query"<<endl;
        outpacket->setRcode(RCode::FormErr);
        sendPacket(outpacket,outsock);
        return 0;
      }
    } else if (rr->d_type != QType::TSIG && rr->d_type != QType::OPT) {
      L<<Logger::Error<<"Additional records in IXFR query, type: "<<QType(rr->d_type).getName()<<endl;
      outpacket->setRcode(RCode::FormErr);
      sendPacket(outpacket,outsock);
      return 0;
    }
  }

  L<<Logger::Error<<"IXFR of domain '"<<q->qdomain<<"' initiated by "<<q->getRemote()<<" with serial "<<serial<<endl;

  // determine if zone exists and AXFR is allowed using existing backend before spawning a new backend.
  SOAData sd;
  {
    Lock l(&s_plock);
    DLOG(L<<"Looking for SOA"<<endl); // find domain_id via SOA and list complete domain. No SOA, no IXFR
    if(!s_P) {
      L<<Logger::Error<<"TCP server is without backend connections in doIXFR, launching"<<endl;
      s_P=new PacketHandler;
    }

    // canDoAXFR does all the ACL checks, and has the if(disable-axfr) shortcut, call it first.
    if(!canDoAXFR(q) || !s_P->getBackend()->getSOAUncached(q->qdomain, sd)) {
      L<<Logger::Error<<"IXFR of domain '"<<q->qdomain<<"' failed: not authoritative"<<endl;
      outpacket->setRcode(9); // 'NOTAUTH'
      sendPacket(outpacket,outsock);
      return 0;
    }
  }

  DNSSECKeeper dk;
  NSEC3PARAMRecordContent ns3pr;
  bool narrow;

  dk.clearCaches(q->qdomain);
  bool securedZone = dk.isSecuredZone(q->qdomain);
  if(dk.getNSEC3PARAM(q->qdomain, &ns3pr, &narrow)) {
    if(narrow) {
      L<<Logger::Error<<"Not doing IXFR of an NSEC3 narrow zone."<<endl;
      L<<Logger::Error<<"IXFR of domain '"<<q->qdomain<<"' denied to "<<q->getRemote()<<endl;
      outpacket->setRcode(RCode::Refused);
      sendPacket(outpacket,outsock);
      return 0;
    }
  }

  string target = q->qdomain;

  UeberBackend db;
  if(!db.getSOAUncached(target, sd)) {
    L<<Logger::Error<<"IXFR of domain '"<<target<<"' failed: not authoritative in second instance"<<endl;
    outpacket->setRcode(RCode::NotAuth);
    sendPacket(outpacket,outsock);
    return 0;
  }

  string soaedit;
  dk.getFromMeta(target, "SOA-EDIT", soaedit);
  if (!rfc1982LessThan(serial, calculateEditSOA(sd, soaedit))) {
    TSIGRecordContent trc;
    string tsigkeyname, tsigsecret;

    q->getTSIGDetails(&trc, &tsigkeyname, 0);

    if(!tsigkeyname.empty()) {
      string tsig64;
      string algorithm=toLowerCanonic(trc.d_algoName);
      if (algorithm == "hmac-md5.sig-alg.reg.int")
        algorithm = "hmac-md5";
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

    L<<Logger::Error<<"IXFR of domain '"<<target<<"' to "<<q->getRemote()<<" finished"<<endl;

    return 1;
  }

  L<<Logger::Error<<"IXFR fallback to AXFR for domain '"<<target<<"' our serial "<<sd.serial<<endl;
  return doAXFR(q->qdomain, q, outsock);
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
    throw PDNSException("No local address specified");

  d_ng.toMasks(::arg()["allow-axfr-ips"] );

  signal(SIGPIPE,SIG_IGN);

  for(vector<string>::const_iterator laddr=locals.begin();laddr!=locals.end();++laddr) {
    int s=socket(AF_INET,SOCK_STREAM,0); 
    
    if(s<0) 
      throw PDNSException("Unable to acquire TCP socket: "+stringerror());

    Utility::setCloseOnExec(s);

    ComboAddress local(*laddr, ::arg().asNum("local-port"));
      
    int tmp=1;
    if(setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(char*)&tmp,sizeof tmp)<0) {
      L<<Logger::Error<<"Setsockopt failed"<<endl;
      exit(1);  
    }
    
    if( ::arg().mustDo("non-local-bind") )
	Utility::setBindAny(AF_INET, s);

    if(::bind(s, (sockaddr*)&local, local.getSocklen())<0) {
      close(s);
      if( errno == EADDRNOTAVAIL && ! ::arg().mustDo("local-address-nonexist-fail") ) {
        L<<Logger::Error<<"IPv4 Address " << *laddr << " does not exist on this server - skipping TCP bind" << endl;
        continue;
      } else {
        L<<Logger::Error<<"Unable to bind to TCP socket " << *laddr << ": "<<strerror(errno)<<endl;
        throw PDNSException("Unable to bind to TCP socket");
      }
    }
    
    listen(s,128);
    L<<Logger::Error<<"TCP server bound to "<<local.toStringWithPort()<<endl;
    d_sockets.push_back(s);
    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = s;
    pfd.events = POLLIN;

    d_prfds.push_back(pfd);
  }

  for(vector<string>::const_iterator laddr=locals6.begin();laddr!=locals6.end();++laddr) {
    int s=socket(AF_INET6,SOCK_STREAM,0); 

    if(s<0) 
      throw PDNSException("Unable to acquire TCPv6 socket: "+stringerror());

    Utility::setCloseOnExec(s);

    ComboAddress local(*laddr, ::arg().asNum("local-port"));

    int tmp=1;
    if(setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(char*)&tmp,sizeof tmp)<0) {
      L<<Logger::Error<<"Setsockopt failed"<<endl;
      exit(1);  
    }
    if( ::arg().mustDo("non-local-bind") )
	Utility::setBindAny(AF_INET6, s);
    if(setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &tmp, sizeof(tmp)) < 0) {
      L<<Logger::Error<<"Failed to set IPv6 socket to IPv6 only, continuing anyhow: "<<strerror(errno)<<endl;
    }
    if(bind(s, (const sockaddr*)&local, local.getSocklen())<0) {
      close(s);
      if( errno == EADDRNOTAVAIL && ! ::arg().mustDo("local-ipv6-nonexist-fail") ) {
        L<<Logger::Error<<"IPv6 Address " << *laddr << " does not exist on this server - skipping TCP bind" << endl;
        continue;
      } else {
        L<<Logger::Error<<"Unable to bind to TCPv6 socket" << *laddr << ": "<<strerror(errno)<<endl;
        throw PDNSException("Unable to bind to TCPv6 socket");
      }
    }
    
    listen(s,128);
    L<<Logger::Error<<"TCPv6 server bound to "<<local.toStringWithPort()<<endl; // this gets %eth0 right
    d_sockets.push_back(s);

    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = s;
    pfd.events = POLLIN;

    d_prfds.push_back(pfd);
  }
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

            if(pthread_create(&tid, 0, &doConnection, reinterpret_cast<void*>(fd))) {
              L<<Logger::Error<<"Error creating thread: "<<stringerror()<<endl;
              d_connectionroom_sem->post();
            }
          }
        }
      }
    }
  }
  catch(PDNSException &AE) {
    L<<Logger::Error<<"TCP Nameserver thread dying because of fatal error: "<<AE.reason<<endl;
  }
  catch(...) {
    L<<Logger::Error<<"TCPNameserver dying because of an unexpected fatal error"<<endl;
  }
  exit(1); // take rest of server with us
}


