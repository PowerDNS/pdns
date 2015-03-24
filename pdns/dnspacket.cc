/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2001 - 2015  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

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
#include "utility.hh"
#include <cstdio>
#include <cstdlib>
#include <sys/types.h>
#include <iostream>  
#include <string>
#include <errno.h>
#include <boost/tokenizer.hpp>
#include <boost/algorithm/string.hpp>
#include <algorithm>
#include <boost/foreach.hpp>
#include "dnsseckeeper.hh"
#include "dns.hh"
#include "dnsbackend.hh"
#include "pdnsexception.hh"
#include "dnspacket.hh"
#include "logger.hh"
#include "arguments.hh"
#include "dnswriter.hh"
#include "dnsparser.hh"
#include "dnsrecords.hh"
#include "dnssecinfra.hh" 
#include "base64.hh"
#include "ednssubnet.hh"

bool DNSPacket::s_doEDNSSubnetProcessing;
uint16_t DNSPacket::s_udpTruncationThreshold;
 
DNSPacket::DNSPacket() 
{
  d_wrapped=false;
  d_compress=true;
  d_tcp=false;
  d_wantsnsid=false;
  d_haveednssubnet = false;
  d_dnssecOk=false;
}

const string& DNSPacket::getString()
{
  if(!d_wrapped)
    wrapup();

  return d_rawpacket;
}

string DNSPacket::getRemote() const
{
  return d_remote.toString();
}

uint16_t DNSPacket::getRemotePort() const
{
  return d_remote.sin4.sin_port;
}

DNSPacket::DNSPacket(const DNSPacket &orig)
{
  DLOG(L<<"DNSPacket copy constructor called!"<<endl);
  d_socket=orig.d_socket;
  d_remote=orig.d_remote;
  d_qlen=orig.d_qlen;
  d_dt=orig.d_dt;
  d_compress=orig.d_compress;
  d_tcp=orig.d_tcp;
  qtype=orig.qtype;
  qclass=orig.qclass;
  qdomain=orig.qdomain;
  qdomainwild=orig.qdomainwild;
  qdomainzone=orig.qdomainzone;
  d_maxreplylen = orig.d_maxreplylen;
  d_ednsping = orig.d_ednsping;
  d_wantsnsid = orig.d_wantsnsid;
  d_anyLocal = orig.d_anyLocal;  
  d_eso = orig.d_eso;
  d_haveednssubnet = orig.d_haveednssubnet;
  d_haveednssection = orig.d_haveednssection;
  d_dnssecOk = orig.d_dnssecOk;
  d_rrs=orig.d_rrs;
  
  d_tsigkeyname = orig.d_tsigkeyname;
  d_tsigprevious = orig.d_tsigprevious;
  d_tsigtimersonly = orig.d_tsigtimersonly;
  d_trc = orig.d_trc;
  d_tsigsecret = orig.d_tsigsecret;
  
  d_havetsig = orig.d_havetsig;
  d_wrapped=orig.d_wrapped;

  d_rawpacket=orig.d_rawpacket;
  d=orig.d;
}

void DNSPacket::setRcode(int v)
{
  d.rcode=v;
}

void DNSPacket::setAnswer(bool b)
{
  if(b) {
    d_rawpacket.assign(12,(char)0);
    memset((void *)&d,0,sizeof(d));
    
    d.qr=b;
  }
}

void DNSPacket::setA(bool b)
{
  d.aa=b;
}

void DNSPacket::setID(uint16_t id)
{
  d.id=id;
}

void DNSPacket::setRA(bool b)
{
  d.ra=b;
}

void DNSPacket::setRD(bool b)
{
  d.rd=b;
}

void DNSPacket::setOpcode(uint16_t opcode)
{
  d.opcode=opcode;
}


void DNSPacket::clearRecords()
{
  d_rrs.clear();
}

void DNSPacket::addRecord(const DNSResourceRecord &rr)
{
  // this removes duplicates from the packet in case we are not compressing
  // for AXFR, no such checking is performed!
  if(d_compress)
    for(vector<DNSResourceRecord>::const_iterator i=d_rrs.begin();i!=d_rrs.end();++i) 
      if(rr.qname==i->qname && rr.qtype==i->qtype && rr.content==i->content) {
          return;
      }

  d_rrs.push_back(rr);
}



static int rrcomp(const DNSResourceRecord &A, const DNSResourceRecord &B)
{
  if(A.d_place < B.d_place)
    return 1;

  return 0;
}

vector<DNSResourceRecord*> DNSPacket::getAPRecords()
{
  vector<DNSResourceRecord*> arrs;

  for(vector<DNSResourceRecord>::iterator i=d_rrs.begin();
      i!=d_rrs.end();
      ++i)
    {
      if(i->d_place!=DNSResourceRecord::ADDITIONAL && 
         (i->qtype.getCode()==QType::MX ||
          i->qtype.getCode()==QType::NS ||
          i->qtype.getCode()==QType::SRV))
        {
          arrs.push_back(&*i);
        }
    }

  return arrs;

}

vector<DNSResourceRecord*> DNSPacket::getAnswerRecords()
{
  vector<DNSResourceRecord*> arrs;

  for(vector<DNSResourceRecord>::iterator i=d_rrs.begin();
      i!=d_rrs.end();
      ++i)
    {
      if(i->d_place!=DNSResourceRecord::ADDITIONAL) 
        arrs.push_back(&*i);
    }
  return arrs;
}


void DNSPacket::setCompress(bool compress)
{
  d_compress=compress;
  d_rawpacket.reserve(65000);
  d_rrs.reserve(200);
}

bool DNSPacket::couldBeCached()
{
  return d_ednsping.empty() && !d_wantsnsid && qclass==QClass::IN;
}

unsigned int DNSPacket::getMinTTL()
{
  unsigned int minttl = UINT_MAX;
  BOOST_FOREACH(DNSResourceRecord rr, d_rrs) {
  if (rr.ttl < minttl)
      minttl = rr.ttl;
  }

  return minttl;
}

bool DNSPacket::isEmpty()
{
  return (d_rrs.empty());
}

/** Must be called before attempting to access getData(). This function stuffs all resource
 *  records found in rrs into the data buffer. It also frees resource records queued for us.
 */
void DNSPacket::wrapup()
{
  if(d_wrapped) {
    return;
  }

  DNSResourceRecord rr;
  vector<DNSResourceRecord>::iterator pos;

  // we now need to order rrs so that the different sections come at the right place
  // we want a stable sort, based on the d_place field

  stable_sort(d_rrs.begin(),d_rrs.end(), rrcomp);
  static bool mustNotShuffle = ::arg().mustDo("no-shuffle");

  if(!d_tcp && !mustNotShuffle) {
    shuffle(d_rrs);
  }
  d_wrapped=true;

  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, qdomain, qtype.getCode(), qclass);

  pw.getHeader()->rcode=d.rcode;
  pw.getHeader()->opcode = d.opcode;
  pw.getHeader()->aa=d.aa;
  pw.getHeader()->ra=d.ra;
  pw.getHeader()->qr=d.qr;
  pw.getHeader()->id=d.id;
  pw.getHeader()->rd=d.rd;
  pw.getHeader()->tc=d.tc;
  
  DNSPacketWriter::optvect_t opts;
  if(d_wantsnsid) {
    const static string mode_server_id=::arg()["server-id"];
    if(mode_server_id != "disabled") {
      opts.push_back(make_pair(3, mode_server_id));
    }
  }

  if(!d_ednsping.empty()) {
    opts.push_back(make_pair(4, d_ednsping));
  }
  
  
  if(!d_rrs.empty() || !opts.empty() || d_haveednssubnet || d_haveednssection) {
    try {
      uint8_t maxScopeMask=0;
      for(pos=d_rrs.begin(); pos < d_rrs.end(); ++pos) {
        maxScopeMask = max(maxScopeMask, pos->scopeMask);

        if(!pos->content.empty() && pos->qtype.getCode()==QType::TXT && pos->content[0]!='"') {
          pos->content="\""+pos->content+"\"";
        }
        if(pos->content.empty())  // empty contents confuse the MOADNS setup
          pos->content=".";
        
        pw.startRecord(pos->qname, pos->qtype.getCode(), pos->ttl, pos->qclass, (DNSPacketWriter::Place)pos->d_place); 
        shared_ptr<DNSRecordContent> drc(DNSRecordContent::mastermake(pos->qtype.getCode(), pos->qclass, pos->content));
              drc->toPacket(pw);
        if(pw.size() + 20U > (d_tcp ? 65535 : getMaxReplyLen())) { // 20 = room for EDNS0
          pw.rollback();
          if(pos->d_place == DNSResourceRecord::ANSWER || pos->d_place == DNSResourceRecord::AUTHORITY) {
            pw.getHeader()->tc=1;
          }
          goto noCommit;
        }
      }

      // if(!pw.getHeader()->tc) // protect against double commit from addSignature

      if(!d_rrs.empty()) pw.commit();

      noCommit:;
      
      if(d_haveednssubnet) {
        string makeEDNSSubnetOptsString(const EDNSSubnetOpts& eso);
        EDNSSubnetOpts eso = d_eso;
        eso.scope = Netmask(eso.source.getNetwork(), maxScopeMask);
    
        string opt = makeEDNSSubnetOptsString(eso);
        opts.push_back(make_pair(8, opt)); // 'EDNS SUBNET'
      }

      if(!opts.empty() || d_haveednssection || d_dnssecOk)
      {
        pw.addOpt(s_udpTruncationThreshold, 0, d_dnssecOk ? EDNSOpts::DNSSECOK : 0, opts);
        pw.commit();
      }
    }
    catch(std::exception& e) {
      L<<Logger::Warning<<"Exception: "<<e.what()<<endl;
      throw;
    }
  }
  
  if(!d_trc.d_algoName.empty())
    addTSIG(pw, &d_trc, d_tsigkeyname, d_tsigsecret, d_tsigprevious, d_tsigtimersonly);
  
  d_rawpacket.assign((char*)&packet[0], packet.size());

  // copy RR counts so LPE can read them
  d.qdcount = pw.getHeader()->qdcount;
  d.ancount = pw.getHeader()->ancount;
  d.nscount = pw.getHeader()->nscount;
  d.arcount = pw.getHeader()->arcount;
}

void DNSPacket::setQuestion(int op, const string &qd, int newqtype)
{
  memset(&d,0,sizeof(d));
  d.id=Utility::random();
  d.rd=d.tc=d.aa=false;
  d.qr=false;
  d.qdcount=1; // is htons'ed later on
  d.ancount=d.arcount=d.nscount=0;
  d.opcode=op;
  qdomain=qd;
  qtype=newqtype;
}

/** convenience function for creating a reply packet from a question packet. Do not forget to delete it after use! */
DNSPacket *DNSPacket::replyPacket() const
{
  DNSPacket *r=new DNSPacket;
  r->setSocket(d_socket);
  r->d_anyLocal=d_anyLocal;
  r->setRemote(&d_remote);
  r->setAnswer(true);  // this implies the allocation of the header
  r->setA(true); // and we are authoritative
  r->setRA(0); // no recursion available
  r->setRD(d.rd); // if you wanted to recurse, answer will say you wanted it 
  r->setID(d.id);
  r->setOpcode(d.opcode);

  r->d_dt=d_dt;
  r->d.qdcount=1;
  r->d_tcp = d_tcp;
  r->qdomain = qdomain;
  r->qtype = qtype;
  r->qclass = qclass;
  r->d_maxreplylen = d_maxreplylen;
  r->d_ednsping = d_ednsping;
  r->d_wantsnsid = d_wantsnsid;
  r->d_dnssecOk = d_dnssecOk;
  r->d_eso = d_eso;
  r->d_haveednssubnet = d_haveednssubnet;
  r->d_haveednssection = d_haveednssection;
 
  if(!d_tsigkeyname.empty()) {
    r->d_tsigkeyname = d_tsigkeyname;
    r->d_tsigprevious = d_tsigprevious;
    r->d_trc = d_trc;
    r->d_tsigsecret = d_tsigsecret;
    r->d_tsigtimersonly = d_tsigtimersonly;
  }
  r->d_havetsig = d_havetsig;
  return r;
}

void DNSPacket::spoofQuestion(const DNSPacket *qd)
{
  d_wrapped=true; // if we do this, don't later on wrapup
  
  int labellen;
  string::size_type i=sizeof(d);

  for(;;) {
    labellen = qd->d_rawpacket[i];
    if(!labellen) break;
    i++;
    d_rawpacket.replace(i, labellen, qd->d_rawpacket, i, labellen);
    i = i + labellen;
  }
}

int DNSPacket::noparse(const char *mesg, int length)
{
  d_rawpacket.assign(mesg,length); 
  if(length < 12) { 
    L << Logger::Warning << "Ignoring packet: too short ("<<length<<" < 12) from "
      << d_remote.toStringWithPort()<< endl;
    return -1;
  }
  d_wantsnsid=false;
  d_ednsping.clear();
  d_maxreplylen=512;
  memcpy((void *)&d,(const void *)d_rawpacket.c_str(),12);
  return 0;
}

void DNSPacket::setTSIGDetails(const TSIGRecordContent& tr, const string& keyname, const string& secret, const string& previous, bool timersonly)
{
  d_trc=tr;
  d_tsigkeyname = keyname;
  d_tsigsecret = secret;
  d_tsigprevious = previous;
  d_tsigtimersonly=timersonly;
}

bool DNSPacket::getTSIGDetails(TSIGRecordContent* trc, string* keyname, string* message) const
{
  MOADNSParser mdp(d_rawpacket);

  if(!mdp.getTSIGPos()) 
    return false;
  
  bool gotit=false;
  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {          
    if(i->first.d_type == QType::TSIG) {
      *trc = *boost::dynamic_pointer_cast<TSIGRecordContent>(i->first.d_content);
      
      gotit=true;
      *keyname = i->first.d_label;
      if(!keyname->empty())
        keyname->resize(keyname->size()-1); // drop the trailing dot
    }
  }
  if(!gotit)
    return false;
  if(message)
    *message = makeTSIGMessageFromTSIGPacket(d_rawpacket, mdp.getTSIGPos(), *keyname, *trc, d_tsigprevious, false); // if you change rawpacket to getString it breaks!
  
  return true;
}

bool DNSPacket::getTKEYRecord(TKEYRecordContent *tr, string *keyname) const
{
  MOADNSParser mdp(d_rawpacket);
  bool gotit=false;

  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {
    if (gotit) {
      L<<Logger::Error<<"More than one TKEY record found in query"<<endl;
      return false;
    }

    if(i->first.d_type == QType::TKEY) {
      *tr = *boost::dynamic_pointer_cast<TKEYRecordContent>(i->first.d_content);
      *keyname = i->first.d_label;
      gotit=true;
    }
  }

  return gotit;
}

/** This function takes data from the network, possibly received with recvfrom, and parses
    it into our class. Results of calling this function multiple times on one packet are
    unknown. Returns -1 if the packet cannot be parsed.
*/
int DNSPacket::parse(const char *mesg, int length)
try
{
  d_rawpacket.assign(mesg,length); 
  d_wrapped=true;
  if(length < 12) { 
    L << Logger::Warning << "Ignoring packet: too short from "
      << getRemote() << endl;
    return -1;
  }

  MOADNSParser mdp(d_rawpacket);
  EDNSOpts edo;

  // ANY OPTION WHICH *MIGHT* BE SET DOWN BELOW SHOULD BE CLEARED FIRST!

  d_wantsnsid=false;
  d_dnssecOk=false;
  d_ednsping.clear();
  d_havetsig = mdp.getTSIGPos();
  d_haveednssubnet = false;
  d_haveednssection = false;
  

  if(getEDNSOpts(mdp, &edo)) {
    d_haveednssection=true;
    d_maxreplylen=std::min(edo.d_packetsize, s_udpTruncationThreshold);
//    cerr<<edo.d_Z<<endl;
    if(edo.d_Z & EDNSOpts::DNSSECOK)
      d_dnssecOk=true;

    for(vector<pair<uint16_t, string> >::const_iterator iter = edo.d_options.begin();
        iter != edo.d_options.end(); 
        ++iter) {
      if(iter->first == 3) {// 'EDNS NSID'
        d_wantsnsid=1;
      }
      else if(iter->first == 5) {// 'EDNS PING'
        d_ednsping = iter->second;
      }
      else if(s_doEDNSSubnetProcessing && (iter->first == 8)) { // 'EDNS SUBNET'
        if(getEDNSSubnetOptsFromString(iter->second, &d_eso)) {
          //cerr<<"Parsed, source: "<<d_eso.source.toString()<<", scope: "<<d_eso.scope.toString()<<", family = "<<d_eso.scope.getNetwork().sin4.sin_family<<endl;
          d_haveednssubnet=true;
        } 
      }
      else {
        // cerr<<"Have an option #"<<iter->first<<": "<<makeHexDump(iter->second)<<endl;
      }
    }
  }
  else  {
    d_maxreplylen=512;
  }

  memcpy((void *)&d,(const void *)d_rawpacket.c_str(),12);
  qdomain=mdp.d_qname;
  if(!qdomain.empty()) // strip dot
    boost::erase_tail(qdomain, 1);

  if(!ntohs(d.qdcount)) {
    if(!d_tcp) {
      L << Logger::Warning << "No question section in packet from " << getRemote() <<", error="<<RCode::to_s(d.rcode)<<endl;
      return -1;
    }
  }
  
  qtype=mdp.d_qtype;
  qclass=mdp.d_qclass;
  return 0;
}
catch(std::exception& e) {
  return -1;
}

unsigned int DNSPacket::getMaxReplyLen()
{
  return d_maxreplylen;
}

void DNSPacket::setMaxReplyLen(int bytes)
{
  d_maxreplylen=bytes;
}

//! Use this to set where this packet was received from or should be sent to
void DNSPacket::setRemote(const ComboAddress *s)
{
  d_remote=*s;
}

bool DNSPacket::hasEDNSSubnet()
{
  return d_haveednssubnet;
}

bool DNSPacket::hasEDNS() 
{
  return d_haveednssection;
}

Netmask DNSPacket::getRealRemote() const
{
  if(d_haveednssubnet)
    return d_eso.source;
  return Netmask(d_remote);
}

void DNSPacket::setSocket(Utility::sock_t sock)
{
  d_socket=sock;
}

void DNSPacket::commitD()
{
  d_rawpacket.replace(0,12,(char *)&d,12); // copy in d
}

bool checkForCorrectTSIG(const DNSPacket* q, UeberBackend* B, string* keyname, string* secret, TSIGRecordContent* trc)
{
  string message;

  q->getTSIGDetails(trc, keyname, &message);
  int64_t now = time(0);
  if(abs((int64_t)trc->d_time - now) > trc->d_fudge) {
    L<<Logger::Error<<"Packet for '"<<q->qdomain<<"' denied: TSIG (key '"<<*keyname<<"') time delta "<< abs(trc->d_time - now)<<" > 'fudge' "<<trc->d_fudge<<endl;
    return false;
  }

  string algoName = toLowerCanonic(trc->d_algoName);
  if (algoName == "hmac-md5.sig-alg.reg.int")
    algoName = "hmac-md5";

  string secret64;
  if(!B->getTSIGKey(*keyname, &algoName, &secret64)) {
    L<<Logger::Error<<"Packet for domain '"<<q->qdomain<<"' denied: can't find TSIG key with name '"<<*keyname<<"' and algorithm '"<<algoName<<"'"<<endl;
    return false;
  }
  if (trc->d_algoName == "hmac-md5")
    trc->d_algoName += ".sig-alg.reg.int.";

  TSIGHashEnum algo;
  if(!getTSIGHashEnum(trc->d_algoName, algo)) {
     L<<Logger::Error<<"Unsupported TSIG HMAC algorithm " << trc->d_algoName << endl;
     return false;
  }

  B64Decode(secret64, *secret);
  bool result=calculateHMAC(*secret, message, algo) == trc->d_mac;
  if(!result) {
    L<<Logger::Error<<"Packet for domain '"<<q->qdomain<<"' denied: TSIG signature mismatch using '"<<*keyname<<"' and algorithm '"<<trc->d_algoName<<"'"<<endl;
  }

  return result;
}
