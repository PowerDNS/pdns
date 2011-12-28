/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2011 PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation.

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
#include "tcpreceiver.hh"
#include "ahuexception.hh"
#include "statbag.hh"
#include "arguments.hh"
#include "base64.hh"
#include "dnswriter.hh"
#include "dnsparser.hh"
#include <boost/shared_ptr.hpp>
#include <boost/foreach.hpp>
#include "dns_random.hh"

#include "namespaces.hh"

int sendNotification(int sock, const string& domain, const ComboAddress& remote, uint16_t id)
{
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, domain, QType::SOA, 1, Opcode::Notify);
  pw.getHeader()->id = id;
  pw.getHeader()->aa = true; 

  if(sendto(sock, &packet[0], packet.size(), 0, (struct sockaddr*)(&remote), remote.getSocklen())<0) {
    throw ResolverException("Unable to send notify to "+remote.toStringWithPort()+": "+stringerror());
  }
  return true;
}

int makeQuerySocket(const ComboAddress& local, bool udpOrTCP)
{
  ComboAddress ourLocal(local);
  static uint16_t port_counter=5000;
  port_counter++; // this makes us use a new port for each query, fixes ticket #2
  
  int sock=socket(ourLocal.sin4.sin_family, udpOrTCP ? SOCK_DGRAM : SOCK_STREAM, 0);
  Utility::setCloseOnExec(sock);
  if(sock < 0)
    unixDie("Creating local resolver socket for "+ourLocal.toString());

  if(!udpOrTCP) {
    int tries=10;
    while(--tries) {
      ourLocal.sin4.sin_port = htons(10000+(dns_random(10000)));
    
      if (::bind(sock, (struct sockaddr *)&ourLocal, ourLocal.getSocklen()) >= 0) 
        break;
    }
    if(!tries) {
      Utility::closesocket(sock);
      throw AhuException("Resolver binding to local socket on "+ourLocal.toString()+": "+stringerror());
    }
  }
  else {
    ourLocal.sin4.sin_port = 0;
    if(::bind(sock, (struct sockaddr *)&ourLocal, ourLocal.getSocklen()) < 0)
      throw AhuException("Resolver binding to local socket on "+ourLocal.toString()+": "+stringerror());
  }
  return sock;
}

Resolver::Resolver()
try
{
  d_sock4 = d_sock6 = 0;
  d_sock4 = makeQuerySocket(ComboAddress(::arg()["query-local-address"]), true);
  if(!::arg()["query-local-address6"].empty())
    d_sock6 = makeQuerySocket(ComboAddress(::arg()["query-local-address6"]), true);
  else 
    d_sock6 = -1;
  d_timeout=500000;
}
catch(...) {
  if(d_sock4>=0)
    close(d_sock4);
  throw;
}

Resolver::~Resolver()
{
  if(d_sock4>=0)
    Utility::closesocket(d_sock4);
  if(d_sock6>=0)
    Utility::closesocket(d_sock6);
}

uint16_t Resolver::sendResolve(const ComboAddress& remote, const char *domain, int type, bool dnssecOK, 
                               const string& tsigkeyname, const string& tsigalgorithm, 
                               const string& tsigsecret)
{
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, domain, type);
  pw.getHeader()->id = d_randomid = dns_random(0xffff);
  
  if(dnssecOK) {
    pw.addOpt(2800, 0, EDNSOpts::DNSSECOK);
    pw.commit();
  }
  
  if(!tsigkeyname.empty()) {
    // cerr<<"Adding TSIG to notification, key name: '"<<tsigkeyname<<"', algo: '"<<tsigalgorithm<<"', secret: "<<Base64Encode(tsigsecret)<<endl;
    TSIGRecordContent trc;
    trc.d_algoName = tsigalgorithm + ".sig-alg.reg.int.";
    trc.d_time = time(0);
    trc.d_fudge = 300;
    trc.d_origID=ntohs(d_randomid);
    trc.d_eRcode=0;
    addTSIG(pw, &trc, tsigkeyname, tsigsecret, "", false);
  }
    
  int sock = remote.sin4.sin_family == AF_INET ? d_sock4 : d_sock6;
  
  if(sendto(sock, &packet[0], packet.size(), 0, (struct sockaddr*)(&remote), remote.getSocklen()) < 0) {
    throw ResolverException("Unable to ask query of "+remote.toStringWithPort()+": "+stringerror());
  }
  return d_randomid;
}

static int parseResult(MOADNSParser& mdp, const std::string& origQname, uint16_t origQtype, uint16_t id, Resolver::res_t* result)
{
  result->clear();
  
  if(mdp.d_header.rcode) 
    return mdp.d_header.rcode;
      
  if(!origQname.empty()) {  // not AXFR
    if(mdp.d_header.id != id) 
      throw ResolverException("Remote nameserver replied with wrong id");
    if(mdp.d_header.qdcount != 1)
      throw ResolverException("resolver: received answer with wrong number of questions ("+itoa(mdp.d_header.qdcount)+")");
    if(mdp.d_qname != origQname+".")
      throw ResolverException(string("resolver: received an answer to another question (")+mdp.d_qname+"!="+ origQname+".)");
  }
    
  vector<DNSResourceRecord> ret; 
  DNSResourceRecord rr;
  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {          
    rr.qname = i->first.d_label;
    if(!rr.qname.empty())
      boost::erase_tail(rr.qname, 1); // strip .
    rr.qtype = i->first.d_type;
    rr.ttl = i->first.d_ttl;
    rr.content = i->first.d_content->getZoneRepresentation();
    rr.priority = 0;
    
    uint16_t qtype=rr.qtype.getCode();

    if(!rr.content.empty() && (qtype==QType::MX || qtype==QType::NS || qtype==QType::CNAME))
      boost::erase_tail(rr.content, 1);

    if(rr.qtype.getCode() == QType::MX) {
      vector<string> parts;
      stringtok(parts, rr.content);
      rr.priority = atoi(parts[0].c_str());
      if(parts.size() > 1)
        rr.content=parts[1];
    } else if(rr.qtype.getCode() == QType::SRV) {
      rr.priority = atoi(rr.content.c_str());
      vector<pair<string::size_type, string::size_type> > fields;
      vstringtok(fields, rr.content, " ");
      if(fields.size()==4)
        rr.content=string(rr.content.c_str() + fields[1].first, fields[3].second - fields[1].first);
    }
    result->push_back(rr);
  }
  
  return 0;
}

bool Resolver::tryGetSOASerial(string* domain, uint32_t *theirSerial, uint32_t *theirInception, uint32_t *theirExpire, uint16_t* id)
{
  Utility::setNonBlocking( d_sock4 );
  Utility::setNonBlocking( d_sock6 );
  
  int sock;
  if(!waitFor2Data(d_sock4, d_sock6, 0, 250000, &sock)) // lame function, I know.. 
    return false;
  
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
  
  MOADNSParser mdp((char*)buf, err);
  *id=mdp.d_header.id;
  *domain = stripDot(mdp.d_qname);
  
  if(mdp.d_answers.empty())
    throw ResolverException("Query to '" + fromaddr.toStringWithPort() + "' for SOA of '" + *domain + "' produced no results (error code: "+strrcode(mdp.d_header.rcode)+")");
  
  if(mdp.d_qtype != QType::SOA)
    throw ResolverException("Query to '" + fromaddr.toStringWithPort() + "' for SOA of '" + *domain + "' returned wrong record type");

  *theirInception = *theirExpire = 0;
  bool gotSOA=false;
  BOOST_FOREACH(const MOADNSParser::answers_t::value_type& drc, mdp.d_answers) {
    if(drc.first.d_type == QType::SOA) {
      shared_ptr<SOARecordContent> src=boost::dynamic_pointer_cast<SOARecordContent>(drc.first.d_content);
      *theirSerial=src->d_st.serial;
      gotSOA = true;
    }
    if(drc.first.d_type == QType::RRSIG) {
      shared_ptr<RRSIGRecordContent> rrc=boost::dynamic_pointer_cast<RRSIGRecordContent>(drc.first.d_content);
      if(rrc->d_type == QType::SOA) {
	*theirInception= std::max(*theirInception, rrc->d_siginception);
	*theirExpire = std::max(*theirExpire, rrc->d_sigexpire);
      }
    }
  }
  if(!gotSOA)
    throw ResolverException("Query to '" + fromaddr.toString() + "' for SOA of '" + *domain + "' did not return a SOA");
  return true;
}

int Resolver::resolve(const string &ipport, const char *domain, int type, Resolver::res_t* res)
{
  try {
    ComboAddress to(ipport, 53);

    int id = sendResolve(to, domain, type);
    int sock =  to.sin4.sin_family == AF_INET ? d_sock4 : d_sock6;
    int err=waitForData(sock, 0, 7500000); 
  
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
  
    MOADNSParser mdp(buffer, len);
    return parseResult(mdp, domain, type, id, res);
  }
  catch(ResolverException &re) {
    throw ResolverException(re.reason+" from "+ipport);
  }
  return -1;
}



void Resolver::getSoaSerial(const string &ipport, const string &domain, uint32_t *serial)
{
  vector<DNSResourceRecord> res;
  int ret = resolve(ipport, domain.c_str(), QType::SOA, &res);
  
  if(ret || res.empty())
    throw ResolverException("Query to '" + ipport + "' for SOA of '" + domain + "' produced no answers");

  if(res[0].qtype.getCode() != QType::SOA) 
    throw ResolverException("Query to '" + ipport + "' for SOA of '" + domain + "' produced a "+res[0].qtype.getName()+" record");

  vector<string>parts;
  stringtok(parts, res[0].content);
  if(parts.size()<3)
    throw ResolverException("Query to '" + ipport + "' for SOA of '" + domain + "' produced an unparseable response");
  
  *serial=(uint32_t)atol(parts[2].c_str());
}

AXFRRetriever::AXFRRetriever(const ComboAddress& remote, const string& domain, const string& tsigkeyname, const string& tsigalgorithm, 
  const string& tsigsecret)
: d_tsigkeyname(tsigkeyname), d_tsigsecret(tsigsecret)
{
  ComboAddress local;
  if(remote.sin4.sin_family == AF_INET)
    local=ComboAddress(::arg()["query-local-address"]);
  else if(!::arg()["query-local-address6"].empty())
    local=ComboAddress(::arg()["query-local-address6"]);
  else
    local=ComboAddress("::");
  d_sock = -1;
  try {
    d_sock = makeQuerySocket(local, false); // make a TCP socket
    d_buf = shared_array<char>(new char[65536]);
    d_remote = remote; // mostly for error reporting
    this->connect();
    d_soacount = 0;
  
    vector<uint8_t> packet;
    DNSPacketWriter pw(packet, domain, QType::AXFR);
    pw.getHeader()->id = dns_random(0xffff);
  
    if(!tsigkeyname.empty()) {
      d_trc.d_algoName = tsigalgorithm + ".sig-alg.reg.int.";
      d_trc.d_time = time(0);
      d_trc.d_fudge = 300;
      d_trc.d_origID=ntohs(pw.getHeader()->id);
      d_trc.d_eRcode=0;
      addTSIG(pw, &d_trc, tsigkeyname, tsigsecret, "", false);
    }
  
    uint16_t replen=htons(packet.size());
    Utility::iovec iov[2];
    iov[0].iov_base=(char*)&replen;
    iov[0].iov_len=2;
    iov[1].iov_base=(char*)&packet[0];
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
    throw;
  }
}

AXFRRetriever::~AXFRRetriever()
{
  close(d_sock);
}

int AXFRRetriever::getChunk(Resolver::res_t &res)
{
  if(d_soacount > 1)
    return false;
  // d_sock is connected and is about to spit out a packet
  int len=getLength();
  
  if(len<0)
    throw ResolverException("EOF trying to read axfr chunk from remote TCP client");
  
  timeoutReadn(len); 

  MOADNSParser mdp(d_buf.get(), len);
  
  if(!d_soacount && !d_tsigkeyname.empty()) { // TSIG verify first message
    string theirMac;
    BOOST_FOREACH(const MOADNSParser::answers_t::value_type& answer, mdp.d_answers) {
      if(answer.first.d_type == QType::TSIG) {
        shared_ptr<TSIGRecordContent> trc = boost::dynamic_pointer_cast<TSIGRecordContent>(answer.first.d_content);
        theirMac = trc->d_mac;
        d_trc.d_time = trc->d_time;
      }
    }
    if(theirMac.empty())
      throw ResolverException("No TSIG on AXFR response from "+d_remote.toStringWithPort()+" , should be signed with TSIG key '"+d_tsigkeyname+"'");
      
    string message = makeTSIGMessageFromTSIGPacket(string(d_buf.get(), len), mdp.getTSIGPos(), d_tsigkeyname, d_trc, d_trc.d_mac, false); // insert our question MAC
    string ourMac=calculateMD5HMAC(d_tsigsecret, message);
    // ourMac[0]++; // sabotage
    if(ourMac != theirMac) {
      throw ResolverException("Signature failed to validate on AXFR response from "+d_remote.toStringWithPort()+" signed with TSIG key '"+d_tsigkeyname+"'");
    }
  }
  
  int err = parseResult(mdp, "", 0, 0, &res);
  if(err) 
    throw ResolverException("AXFR chunk with a non-zero rcode "+lexical_cast<string>(err));
    
  for(Resolver::res_t::const_iterator i= res.begin(); i!=res.end(); ++i)
    if(i->qtype.getCode()==QType::SOA) {
      d_soacount++;
    }

  if(d_soacount>1 && !res.empty()) // chop off the last SOA
    res.resize(res.size()-1);
  return true;
}

void AXFRRetriever::timeoutReadn(uint16_t bytes)
{
  time_t start=time(0);
  int n=0;
  int numread;
  while(n<bytes) {
    if(waitForData(d_sock, 10-(time(0)-start))<0)
      throw ResolverException("Reading data from remote nameserver over TCP: "+stringerror());

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
  Utility::setNonBlocking( d_sock );

  int err;

  if((err=::connect(d_sock,(struct sockaddr*)&d_remote, d_remote.getSocklen()))<0 && errno!=EINPROGRESS) {
    Utility::closesocket(d_sock);
    d_sock=-1;
    throw ResolverException("connect: "+stringerror());
  }

  if(!err)
    goto done;

  err=waitForRWData(d_sock, false, 10, 0); // wait for writeability
  
  if(!err) {
    Utility::closesocket(d_sock); // timeout
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
  Utility::setBlocking( d_sock );
  // d_sock now connected
}

int AXFRRetriever::getLength()
{
  timeoutReadn(2);
  return (unsigned char)d_buf[0]*256+(unsigned char)d_buf[1];
}

