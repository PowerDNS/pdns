/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "utility.hh"
#include "resolver.hh"
#include <pthread.h>
#include <semaphore.h>
#include <iostream>
#include <errno.h>
#include "misc.hh"
#include <algorithm>
#include <sstream>
#include "dnsrecords.hh"
#include <cstring>
#include <string>
#include <vector>
#include <boost/algorithm/string.hpp>
#include "dns.hh"
#include "qtype.hh"

#include "pdnsexception.hh"
#include "arguments.hh"
#include "base64.hh"
#include "dnswriter.hh"
#include "dnsparser.hh"


#include "dns_random.hh"
#include <poll.h>
#include "gss_context.hh"
#include "namespaces.hh"

int makeQuerySocket(const ComboAddress& local, bool udpOrTCP, bool nonLocalBind)
{
  ComboAddress ourLocal(local);
  
  int sock=socket(ourLocal.sin4.sin_family, udpOrTCP ? SOCK_DGRAM : SOCK_STREAM, 0);
  if(sock < 0) {
    if(errno == EAFNOSUPPORT && local.sin4.sin_family == AF_INET6) {
        return -1;
    }
    unixDie("Creating local resolver socket for "+ourLocal.toString());
  }

  setCloseOnExec(sock);

  if(nonLocalBind)
    Utility::setBindAny(local.sin4.sin_family, sock);

  if(udpOrTCP) {
    // udp, try hard to bind an unpredictable port
    int tries=10;
    while(--tries) {
      ourLocal.sin4.sin_port = htons(10000+(dns_random(10000)));
    
      if (::bind(sock, (struct sockaddr *)&ourLocal, ourLocal.getSocklen()) >= 0) 
        break;
    }
    // cerr<<"bound udp port "<<ourLocal.sin4.sin_port<<", "<<tries<<" tries left"<<endl;

    if(!tries) {
      closesocket(sock);
      throw PDNSException("Resolver binding to local UDP socket on "+ourLocal.toString()+": "+stringerror());
    }
  }
  else {
    // tcp, let the kernel figure out the port
    ourLocal.sin4.sin_port = 0;
    if(::bind(sock, (struct sockaddr *)&ourLocal, ourLocal.getSocklen()) < 0) {
      closesocket(sock);
      throw PDNSException("Resolver binding to local TCP socket on "+ourLocal.toString()+": "+stringerror());
    }
  }
  return sock;
}

Resolver::Resolver()
{
  locals["default4"] = -1;
  locals["default6"] = -1;
  try {
    locals["default4"] = makeQuerySocket(ComboAddress(::arg()["query-local-address"]), true, ::arg().mustDo("non-local-bind"));
    if(!::arg()["query-local-address6"].empty())
      locals["default6"] = makeQuerySocket(ComboAddress(::arg()["query-local-address6"]), true, ::arg().mustDo("non-local-bind"));
  }
  catch(...) {
    if(locals["default4"]>=0)
      close(locals["default4"]);
    throw;
  }
}

Resolver::~Resolver()
{
  for(std::map<std::string,int>::iterator iter = locals.begin(); iter != locals.end(); iter++) {
    if (iter->second >= 0)
      close(iter->second);
  }
}

uint16_t Resolver::sendResolve(const ComboAddress& remote, const ComboAddress& local,
                               const DNSName &domain, int type, bool dnssecOK,
                               const DNSName& tsigkeyname, const DNSName& tsigalgorithm,
                               const string& tsigsecret)
{
  uint16_t randomid;
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, domain, type);
  pw.getHeader()->id = randomid = dns_random(0xffff);

  if(dnssecOK) {
    pw.addOpt(2800, 0, EDNSOpts::DNSSECOK);
    pw.commit();
  }

  if(!tsigkeyname.empty()) {
    // cerr<<"Adding TSIG to notification, key name: '"<<tsigkeyname<<"', algo: '"<<tsigalgorithm<<"', secret: "<<Base64Encode(tsigsecret)<<endl;
    TSIGRecordContent trc;
    if (tsigalgorithm == DNSName("hmac-md5"))
      trc.d_algoName = tsigalgorithm + DNSName("sig-alg.reg.int");
    else
      trc.d_algoName = tsigalgorithm;
    trc.d_time = time(0);
    trc.d_fudge = 300;
    trc.d_origID=ntohs(randomid);
    trc.d_eRcode=0;
    addTSIG(pw, trc, tsigkeyname, tsigsecret, "", false);
  }

  int sock;

  // choose socket based on local
  if (local.sin4.sin_family == 0) {
    // up to us.
    sock = remote.sin4.sin_family == AF_INET ? locals["default4"] : locals["default6"];
  } else {
    std::string lstr = local.toString();
    std::map<std::string, int>::iterator lptr;
    // see if there is a local

    if ((lptr = locals.find(lstr)) != locals.end()) {
      sock = lptr->second;
    } else {
      // try to make socket
      sock = makeQuerySocket(local, true);
      if (sock < 0)
        throw ResolverException("Unable to create socket to "+remote.toStringWithPort()+": "+stringerror());
      setNonBlocking( sock );
      locals[lstr] = sock;
    }
  }

  if(sendto(sock, &packet[0], packet.size(), 0, (struct sockaddr*)(&remote), remote.getSocklen()) < 0) {
    throw ResolverException("Unable to ask query of "+remote.toStringWithPort()+": "+stringerror());
  }
  return randomid;
}

uint16_t Resolver::sendResolve(const ComboAddress& remote, const DNSName &domain,
                               int type, bool dnssecOK,
                               const DNSName& tsigkeyname, const DNSName& tsigalgorithm,
                               const string& tsigsecret)
{
  ComboAddress local;
  local.sin4.sin_family = 0;
  return this->sendResolve(remote, local, domain, type, dnssecOK, tsigkeyname, tsigalgorithm, tsigsecret);
}

static int parseResult(MOADNSParser& mdp, const DNSName& origQname, uint16_t origQtype, uint16_t id, Resolver::res_t* result)
{
  result->clear();

  if(mdp.d_header.rcode)
    return mdp.d_header.rcode;

  if(origQname.countLabels()) {  // not AXFR
    if(mdp.d_header.id != id) 
      throw ResolverException("Remote nameserver replied with wrong id");
    if(mdp.d_header.qdcount != 1)
      throw ResolverException("resolver: received answer with wrong number of questions ("+itoa(mdp.d_header.qdcount)+")");
    if(mdp.d_qname != origQname)
      throw ResolverException(string("resolver: received an answer to another question (")+mdp.d_qname.toString()+"!="+ origQname.toString()+".)");
  }

  vector<DNSResourceRecord> ret;
  DNSResourceRecord rr;
  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {
    rr.qname = i->first.d_name;
    rr.qtype = i->first.d_type;
    rr.ttl = i->first.d_ttl;
    rr.content = i->first.d_content->getZoneRepresentation(true);
    result->push_back(rr);
  }

  return 0;
}

bool Resolver::tryGetSOASerial(DNSName *domain, uint32_t *theirSerial, uint32_t *theirInception, uint32_t *theirExpire, uint16_t* id)
{
  auto fds = std::unique_ptr<struct pollfd[]>(new struct pollfd[locals.size()]);
  size_t i = 0, k;
  int sock;

  for(std::map<string,int>::iterator iter=locals.begin(); iter != locals.end(); iter++, i++) {
    fds[i].fd = iter->second;
    fds[i].events = POLLIN;
  }

  if (poll(fds.get(), i, 250) < 1) { // wait for 0.25s
    return false;
  }

  sock = -1;

  // determine who
  for(k=0;k<i;k++) {
    if ((fds[k].revents & POLLIN) == POLLIN) {
      sock = fds[k].fd;
      break;
    }
  }

  if (sock < 0) return false; // false alarm

  int err;
  ComboAddress fromaddr;
  socklen_t addrlen=fromaddr.getSocklen();
  char buf[3000];
  err = recvfrom(sock, buf, sizeof(buf), 0,(struct sockaddr*)(&fromaddr), &addrlen);
  if(err < 0) {
    if(errno == EAGAIN)
      return false;

    throw ResolverException("recvfrom error waiting for answer: "+stringerror());
  }

  MOADNSParser mdp(false, (char*)buf, err);
  *id=mdp.d_header.id;
  *domain = mdp.d_qname;
  
  if(domain->empty())
    throw ResolverException("SOA query to '" + fromaddr.toStringWithPort() + "' produced response without domain name (RCode: " + RCode::to_s(mdp.d_header.rcode) + ")");

  if(mdp.d_answers.empty())
    throw ResolverException("Query to '" + fromaddr.toStringWithPort() + "' for SOA of '" + domain->toString() + "' produced no results (RCode: " + RCode::to_s(mdp.d_header.rcode) + ")");
  
  if(mdp.d_qtype != QType::SOA)
    throw ResolverException("Query to '" + fromaddr.toStringWithPort() + "' for SOA of '" + domain->toString() + "' returned wrong record type");

  *theirInception = *theirExpire = 0;
  bool gotSOA=false;
  for(const MOADNSParser::answers_t::value_type& drc :  mdp.d_answers) {
    if(drc.first.d_type == QType::SOA) {
      shared_ptr<SOARecordContent> src=getRR<SOARecordContent>(drc.first);
      if (src) {
        *theirSerial=src->d_st.serial;
        gotSOA = true;
      }
    }
    if(drc.first.d_type == QType::RRSIG) {
      shared_ptr<RRSIGRecordContent> rrc=getRR<RRSIGRecordContent>(drc.first);
      if(rrc && rrc->d_type == QType::SOA) {
        *theirInception= std::max(*theirInception, rrc->d_siginception);
        *theirExpire = std::max(*theirExpire, rrc->d_sigexpire);
      }
    }
  }
  if(!gotSOA)
    throw ResolverException("Query to '" + fromaddr.toString() + "' for SOA of '" + domain->toString() + "' did not return a SOA");
  return true;
}

int Resolver::resolve(const string &ipport, const DNSName &domain, int type, Resolver::res_t* res, const ComboAddress &local)
{
  try {
    ComboAddress to(ipport, 53);

    int id = sendResolve(to, local, domain, type);
    int sock;

    // choose socket based on local
    if (local.sin4.sin_family == 0) {
      // up to us.
      sock = to.sin4.sin_family == AF_INET ? locals["default4"] : locals["default6"];
    } else {
      std::string lstr = local.toString();
      std::map<std::string, int>::iterator lptr;
      // see if there is a local

      if ((lptr = locals.find(lstr)) != locals.end()) sock = lptr->second;
      else throw ResolverException("sendResolve did not create socket for " + lstr);
    }

    int err=waitForData(sock, 0, 3000000); 
  
    if(!err) {
      throw ResolverException("Timeout waiting for answer");
    }
    if(err < 0)
      throw ResolverException("Error waiting for answer: "+stringerror());
  
    ComboAddress from;
    socklen_t addrlen = sizeof(from);
    char buffer[3000];
    int len;
    
    if((len=recvfrom(sock, buffer, sizeof(buffer), 0,(struct sockaddr*)(&from), &addrlen)) < 0) 
      throw ResolverException("recvfrom error waiting for answer: "+stringerror());
  
    MOADNSParser mdp(false, buffer, len);
    return parseResult(mdp, domain, type, id, res);
  }
  catch(ResolverException &re) {
    throw ResolverException(re.reason+" from "+ipport);
  }
  return -1;
}

int Resolver::resolve(const string &ipport, const DNSName &domain, int type, Resolver::res_t* res) {
  ComboAddress local;
  local.sin4.sin_family = 0;
  return resolve(ipport, domain, type, res, local);
}

void Resolver::getSoaSerial(const string &ipport, const DNSName &domain, uint32_t *serial)
{
  vector<DNSResourceRecord> res;
  int ret = resolve(ipport, domain, QType::SOA, &res);
  
  if(ret || res.empty())
    throw ResolverException("Query to '" + ipport + "' for SOA of '" + domain.toString() + "' produced no answers");

  if(res[0].qtype.getCode() != QType::SOA) 
    throw ResolverException("Query to '" + ipport + "' for SOA of '" + domain.toString() + "' produced a "+res[0].qtype.getName()+" record");

  vector<string>parts;
  stringtok(parts, res[0].content);
  if(parts.size()<3)
    throw ResolverException("Query to '" + ipport + "' for SOA of '" + domain.toString() + "' produced an unparseable response");

  try {
    *serial=pdns_stou(parts[2]);
  }
  catch(const std::out_of_range& oor) {
    throw ResolverException("Query to '" + ipport + "' for SOA of '" + domain.toString() + "' produced an unparseable serial");
  }
}

AXFRRetriever::AXFRRetriever(const ComboAddress& remote,
                             const DNSName& domain,
                             const TSIGTriplet& tt, 
                             const ComboAddress* laddr,
                             size_t maxReceivedBytes)
  : d_tsigVerifier(tt, remote, d_trc), d_receivedBytes(0), d_maxReceivedBytes(maxReceivedBytes)
{
  ComboAddress local;
  if (laddr != NULL) {
    local = (ComboAddress) (*laddr);
  } else {
    if(remote.sin4.sin_family == AF_INET)
      local=ComboAddress(::arg()["query-local-address"]);
    else if(!::arg()["query-local-address6"].empty())
      local=ComboAddress(::arg()["query-local-address6"]);
    else
      local=ComboAddress("::");
  }
  d_sock = -1;
  try {
    d_sock = makeQuerySocket(local, false); // make a TCP socket
    if (d_sock < 0)
      throw ResolverException("Error creating socket for AXFR request to "+d_remote.toStringWithPort());
    d_buf = shared_array<char>(new char[65536]);
    d_remote = remote; // mostly for error reporting
    this->connect();
    d_soacount = 0;
  
    vector<uint8_t> packet;
    DNSPacketWriter pw(packet, domain, QType::AXFR);
    pw.getHeader()->id = dns_random(0xffff);
  
    if(!tt.name.empty()) {
      if (tt.algo == DNSName("hmac-md5"))
        d_trc.d_algoName = tt.algo + DNSName("sig-alg.reg.int");
      else
        d_trc.d_algoName = tt.algo;
      d_trc.d_time = time(0);
      d_trc.d_fudge = 300;
      d_trc.d_origID=ntohs(pw.getHeader()->id);
      d_trc.d_eRcode=0;
      addTSIG(pw, d_trc, tt.name, tt.secret, "", false);
    }
  
    uint16_t replen=htons(packet.size());
    Utility::iovec iov[2];
    iov[0].iov_base=reinterpret_cast<char*>(&replen);
    iov[0].iov_len=2;
    iov[1].iov_base=packet.data();
    iov[1].iov_len=packet.size();
  
    int ret=Utility::writev(d_sock, iov, 2);
    if(ret < 0)
      throw ResolverException("Error sending question to "+d_remote.toStringWithPort()+": "+stringerror());
    if(ret != (int)(2+packet.size())) {
      throw ResolverException("Partial write on AXFR request to "+d_remote.toStringWithPort());
    }
  
    int res = waitForData(d_sock, 10, 0);
    
    if(!res)
      throw ResolverException("Timeout waiting for answer from "+d_remote.toStringWithPort()+" during AXFR");
    if(res<0)
      throw ResolverException("Error waiting for answer from "+d_remote.toStringWithPort()+": "+stringerror());
  }
  catch(...) {
    if(d_sock >= 0)
      close(d_sock);
    d_sock = -1;
    throw;
  }
}

AXFRRetriever::~AXFRRetriever()
{
  close(d_sock);
}



int AXFRRetriever::getChunk(Resolver::res_t &res, vector<DNSRecord>* records) // Implementation is making sure RFC2845 4.4 is followed.
{
  if(d_soacount > 1)
    return false;

  // d_sock is connected and is about to spit out a packet
  int len=getLength();
  if(len<0)
    throw ResolverException("EOF trying to read axfr chunk from remote TCP client");

  if (d_maxReceivedBytes > 0 && (d_maxReceivedBytes - d_receivedBytes) < (size_t) len)
    throw ResolverException("Reached the maximum number of received bytes during AXFR");

  timeoutReadn(len);

  d_receivedBytes += (uint16_t) len;

  MOADNSParser mdp(false, d_buf.get(), len);

  int err;
  if(!records)
    err=parseResult(mdp, DNSName(), 0, 0, &res);
  else {
    records->clear();
    for(const auto& r: mdp.d_answers)
      records->push_back(r.first);
    err = mdp.d_header.rcode;
  }
  
  if(err) 
    throw ResolverException("AXFR chunk error: " + RCode::to_s(err));

  for(const MOADNSParser::answers_t::value_type& answer :  mdp.d_answers)
    if (answer.first.d_type == QType::SOA)
      d_soacount++;
 
  try {
    d_tsigVerifier.check(std::string(d_buf.get(), len), mdp);
  }
  catch(const std::runtime_error& re) {
    throw ResolverException(re.what());
  }

  return true;
}

void AXFRRetriever::timeoutReadn(uint16_t bytes)
{
  time_t start=time(0);
  int n=0;
  int numread;
  while(n<bytes) {
    int res=waitForData(d_sock, 10-(time(0)-start));
    if(res<0)
      throw ResolverException("Reading data from remote nameserver over TCP: "+stringerror());
    if(!res)
      throw ResolverException("Timeout while reading data from remote nameserver over TCP");

    numread=recv(d_sock, d_buf.get()+n, bytes-n, 0);
    if(numread<0)
      throw ResolverException("Reading data from remote nameserver over TCP: "+stringerror());
    if(numread==0)
      throw ResolverException("Remote nameserver closed TCP connection");
    n+=numread;
  }
}

void AXFRRetriever::connect()
{
  setNonBlocking( d_sock );

  int err;

  if((err=::connect(d_sock,(struct sockaddr*)&d_remote, d_remote.getSocklen()))<0 && errno!=EINPROGRESS) {
    try {
      closesocket(d_sock);
    }
    catch(const PDNSException& e) {
      d_sock=-1;
      throw ResolverException("Error closing AXFR socket after connect() failed: "+e.reason);
    }

    throw ResolverException("connect: "+stringerror());
  }

  if(!err)
    goto done;

  err=waitForRWData(d_sock, false, 10, 0); // wait for writeability
  
  if(!err) {
    try {
      closesocket(d_sock); // timeout
    }
    catch(const PDNSException& e) {
      d_sock=-1;
      throw ResolverException("Error closing AXFR socket after timeout: "+e.reason);
    }

    d_sock=-1;
    errno=ETIMEDOUT;
    
    throw ResolverException("Timeout connecting to server");
  }
  else if(err < 0) {
    throw ResolverException("Error connecting: "+string(strerror(err)));
  }
  else {
    Utility::socklen_t len=sizeof(err);
    if(getsockopt(d_sock, SOL_SOCKET,SO_ERROR,(char *)&err,&len)<0)
      throw ResolverException("Error connecting: "+stringerror()); // Solaris

    if(err)
      throw ResolverException("Error connecting: "+string(strerror(err)));
  }
  
 done:
  setBlocking( d_sock );
  // d_sock now connected
}

int AXFRRetriever::getLength()
{
  timeoutReadn(2);
  return (unsigned char)d_buf[0]*256+(unsigned char)d_buf[1];
}

