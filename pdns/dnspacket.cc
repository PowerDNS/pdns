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
#include <cstdio>
#include <cstdlib>
#include <sys/types.h>
#include <iostream>  
#include <string>
#include <boost/tokenizer.hpp>
#include <boost/functional/hash.hpp>
#include <boost/algorithm/string.hpp>
#include <openssl/hmac.h>
#include <algorithm>

#include "dnsseckeeper.hh"
#include "dns.hh"
#include "dnsbackend.hh"
#include "ednsoptions.hh"
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
#include "gss_context.hh"
#include "dns_random.hh"

bool DNSPacket::s_doEDNSSubnetProcessing;
uint16_t DNSPacket::s_udpTruncationThreshold;
 
DNSPacket::DNSPacket(bool isQuery): d_isQuery(isQuery)
{
  memset(&d, 0, sizeof(d));
}

const string& DNSPacket::getString()
{
  if(!d_wrapped)
    wrapup();

  return d_rawpacket;
}

ComboAddress DNSPacket::getRemote() const
{
  return d_remote;
}

uint16_t DNSPacket::getRemotePort() const
{
  return d_remote.sin4.sin_port;
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
  d_dedup.clear();
}

void DNSPacket::addRecord(const DNSZoneRecord &rr)
{
  // this removes duplicates from the packet.
  // in case we are not compressing for AXFR, no such checking is performed!

  if(d_compress) {
    std::string ser = const_cast<DNSZoneRecord&>(rr).dr.d_content->serialize(rr.dr.d_name);
    auto hash = boost::hash< std::pair<DNSName, std::string> >()({rr.dr.d_name, ser});
    if(d_dedup.count(hash)) { // might be a dup
      for(auto i=d_rrs.begin();i!=d_rrs.end();++i) {
        if(rr.dr == i->dr)  // XXX SUPER SLOW
          return;
      }
    }
    d_dedup.insert(hash);
  }

  d_rrs.push_back(rr);
}

vector<DNSZoneRecord*> DNSPacket::getAPRecords()
{
  vector<DNSZoneRecord*> arrs;

  for(vector<DNSZoneRecord>::iterator i=d_rrs.begin();
      i!=d_rrs.end();
      ++i)
    {
      if(i->dr.d_place!=DNSResourceRecord::ADDITIONAL &&
         (i->dr.d_type==QType::MX ||
          i->dr.d_type==QType::NS ||
          i->dr.d_type==QType::SRV))
        {
          arrs.push_back(&*i);
        }
    }
  return arrs;
}

vector<DNSZoneRecord*> DNSPacket::getAnswerRecords()
{
  vector<DNSZoneRecord*> arrs;

  for(vector<DNSZoneRecord>::iterator i=d_rrs.begin();
      i!=d_rrs.end();
      ++i)
    {
      if(i->dr.d_place!=DNSResourceRecord::ADDITIONAL)
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

bool DNSPacket::couldBeCached() const
{
  return !d_wantsnsid && qclass==QClass::IN && !d_havetsig;
}

unsigned int DNSPacket::getMinTTL()
{
  unsigned int minttl = UINT_MAX;
  for(const DNSZoneRecord& rr :  d_rrs) {
  if (rr.dr.d_ttl < minttl)
      minttl = rr.dr.d_ttl;
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

  DNSZoneRecord rr;
  vector<DNSZoneRecord>::iterator pos;

  // we now need to order rrs so that the different sections come at the right place
  // we want a stable sort, based on the d_place field

  stable_sort(d_rrs.begin(),d_rrs.end(), [](const DNSZoneRecord& a, const DNSZoneRecord& b) {
      return a.dr.d_place < b.dr.d_place;
    });
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

  /* optsize is expected to hold an upper bound of data that will be
     added after actual record data - i.e. OPT, TSIG, perhaps one day
     XPF. Because of the way `pw` incrementally writes the packet, we
     cannot easily 'go back' and remove a few records. So, to prevent
     going over our maximum size, we keep our (potential) extra data
     in mind.

     This means that sometimes we'll send TC even if we'd end up with
     a few bytes to spare, but so be it.
    */
  size_t optsize = 0;

  if (d_haveednssection || d_dnssecOk) {
    /* root label (1), type (2), class (2), ttl (4) + rdlen (2) */
    optsize = 11;
  }

  if(d_wantsnsid) {
    const static string mode_server_id=::arg()["server-id"];
    if(mode_server_id != "disabled") {
      opts.push_back(make_pair(EDNSOptionCode::NSID, mode_server_id));
      optsize += EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE + mode_server_id.size();
    }
  }

  if (d_haveednssubnet)
  {
    // this is an upper bound
    optsize += EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE + 2 + 1 + 1; // code+len+family+src len+scope len
    optsize += d_eso.source.isIpv4() ? 4 : 16;
  }

  if (d_trc.d_algoName.countLabels())
  {
    // TSIG is not OPT, but we count it in optsize anyway
    optsize += d_trc.d_algoName.wirelength() + 3 + 1 + 2; // algo + time + fudge + maclen
    optsize += EVP_MAX_MD_SIZE + 2 + 2 + 2 + 0; // mac + origid + ercode + otherdatalen + no other data

    static_assert(EVP_MAX_MD_SIZE <= 64, "EVP_MAX_MD_SIZE is overly huge on this system, please check");
  }

  if(!d_rrs.empty() || !opts.empty() || d_haveednssubnet || d_haveednssection) {
    try {
      uint8_t maxScopeMask=0;
      for(pos=d_rrs.begin(); pos < d_rrs.end(); ++pos) {
        // cerr<<"during wrapup, content=["<<pos->content<<"]"<<endl;
        maxScopeMask = max(maxScopeMask, pos->scopeMask);
        
        pw.startRecord(pos->dr.d_name, pos->dr.d_type, pos->dr.d_ttl, pos->dr.d_class, pos->dr.d_place);
        pos->dr.d_content->toPacket(pw);
        if(pw.size() + optsize > (d_tcp ? 65535 : getMaxReplyLen())) {
          pw.rollback();
          pw.truncate();
          pw.getHeader()->tc=1;
          goto noCommit;
        }
      }

      // if(!pw.getHeader()->tc) // protect against double commit from addSignature

      if(!d_rrs.empty()) pw.commit();

      noCommit:;
      
      if(d_haveednssubnet) {
        EDNSSubnetOpts eso = d_eso;
        eso.scope = Netmask(eso.source.getNetwork(), maxScopeMask);
    
        string opt = makeEDNSSubnetOptsString(eso);
        opts.push_back(make_pair(8, opt)); // 'EDNS SUBNET'
      }

      if(!opts.empty() || d_haveednssection || d_dnssecOk)
      {
        pw.addOpt(s_udpTruncationThreshold, d_ednsrcode, d_dnssecOk ? EDNSOpts::DNSSECOK : 0, opts);
        pw.commit();
      }
    }
    catch(std::exception& e) {
      g_log<<Logger::Warning<<"Exception: "<<e.what()<<endl;
      throw;
    }
  }
  
  if(d_trc.d_algoName.countLabels())
    addTSIG(pw, d_trc, d_tsigkeyname, d_tsigsecret, d_tsigprevious, d_tsigtimersonly);
  
  d_rawpacket.assign((char*)&packet[0], packet.size()); // XXX we could do this natively on a vector..

  // copy RR counts so they can be read later
  d.qdcount = pw.getHeader()->qdcount;
  d.ancount = pw.getHeader()->ancount;
  d.nscount = pw.getHeader()->nscount;
  d.arcount = pw.getHeader()->arcount;
}

void DNSPacket::setQuestion(int op, const DNSName &qd, int newqtype)
{
  memset(&d,0,sizeof(d));
  d.id=dns_random_uint16();
  d.rd=d.tc=d.aa=false;
  d.qr=false;
  d.qdcount=1; // is htons'ed later on
  d.ancount=d.arcount=d.nscount=0;
  d.opcode=op;
  qdomain=qd;
  qtype=newqtype;
}

/** convenience function for creating a reply packet from a question packet. */
std::unique_ptr<DNSPacket> DNSPacket::replyPacket() const
{
  auto r=make_unique<DNSPacket>(false);
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
  r->d_wantsnsid = d_wantsnsid;
  r->d_dnssecOk = d_dnssecOk;
  r->d_eso = d_eso;
  r->d_haveednssubnet = d_haveednssubnet;
  r->d_haveednssection = d_haveednssection;
  r->d_ednsversion = 0;
  r->d_ednsrcode = 0;

  if(d_tsigkeyname.countLabels()) {
    r->d_tsigkeyname = d_tsigkeyname;
    r->d_tsigprevious = d_tsigprevious;
    r->d_trc = d_trc;
    r->d_tsigsecret = d_tsigsecret;
    r->d_tsigtimersonly = d_tsigtimersonly;
  }
  r->d_havetsig = d_havetsig;
  return r;
}

void DNSPacket::spoofQuestion(const DNSPacket& qd)
{
  d_wrapped=true; // if we do this, don't later on wrapup
  
  int labellen;
  string::size_type i=sizeof(d);

  for(;;) {
    labellen = qd.d_rawpacket[i];
    if(!labellen) break;
    i++;
    d_rawpacket.replace(i, labellen, qd.d_rawpacket, i, labellen);
    i = i + labellen;
  }
}

int DNSPacket::noparse(const char *mesg, size_t length)
{
  d_rawpacket.assign(mesg,length); 
  if(length < 12) { 
    g_log << Logger::Debug << "Ignoring packet: too short ("<<length<<" < 12) from "
      << d_remote.toStringWithPort()<< endl;
    return -1;
  }
  d_wantsnsid=false;
  d_maxreplylen=512;
  memcpy((void *)&d,(const void *)d_rawpacket.c_str(),12);
  return 0;
}

void DNSPacket::setTSIGDetails(const TSIGRecordContent& tr, const DNSName& keyname, const string& secret, const string& previous, bool timersonly)
{
  d_trc=tr;
  d_trc.d_origID = (((d.id & 0xFF)<<8) | ((d.id & 0xFF00)>>8));
  d_tsigkeyname = keyname;
  d_tsigsecret = secret;
  d_tsigprevious = previous;
  d_tsigtimersonly=timersonly;
}

bool DNSPacket::getTSIGDetails(TSIGRecordContent* trc, DNSName* keyname, uint16_t* tsigPosOut) const
{
  MOADNSParser mdp(d_isQuery, d_rawpacket);
  uint16_t tsigPos = mdp.getTSIGPos();
  if(!tsigPos)
    return false;
  
  bool gotit=false;
  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {          
    if(i->first.d_type == QType::TSIG && i->first.d_class == QType::ANY) {
      // cast can fail, f.e. if d_content is an UnknownRecordContent.
      shared_ptr<TSIGRecordContent> content = std::dynamic_pointer_cast<TSIGRecordContent>(i->first.d_content);
      if (!content) {
        g_log<<Logger::Error<<"TSIG record has no or invalid content (invalid packet)"<<endl;
        return false;
      }
      *trc = *content;
      *keyname = i->first.d_name;
      gotit=true;
    }
  }
  if(!gotit)
    return false;

  if (tsigPosOut) {
    *tsigPosOut = tsigPos;
  }
  
  return true;
}

bool DNSPacket::getTKEYRecord(TKEYRecordContent *tr, DNSName *keyname) const
{
  MOADNSParser mdp(d_isQuery, d_rawpacket);
  bool gotit=false;

  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {
    if (gotit) {
      g_log<<Logger::Error<<"More than one TKEY record found in query"<<endl;
      return false;
    }

    if(i->first.d_type == QType::TKEY) {
      // cast can fail, f.e. if d_content is an UnknownRecordContent.
      shared_ptr<TKEYRecordContent> content = std::dynamic_pointer_cast<TKEYRecordContent>(i->first.d_content);
      if (!content) {
        g_log<<Logger::Error<<"TKEY record has no or invalid content (invalid packet)"<<endl;
        return false;
      }
      *tr = *content;
      *keyname = i->first.d_name;
      gotit=true;
    }
  }

  return gotit;
}

/** This function takes data from the network, possibly received with recvfrom, and parses
    it into our class. Results of calling this function multiple times on one packet are
    unknown. Returns -1 if the packet cannot be parsed.
*/
int DNSPacket::parse(const char *mesg, size_t length)
try
{
  d_rawpacket.assign(mesg,length); 
  d_wrapped=true;
  if(length < 12) { 
    g_log << Logger::Debug << "Ignoring packet: too short from "
      << getRemote() << endl;
    return -1;
  }

  MOADNSParser mdp(d_isQuery, d_rawpacket);
  EDNSOpts edo;

  // ANY OPTION WHICH *MIGHT* BE SET DOWN BELOW SHOULD BE CLEARED FIRST!

  d_wantsnsid=false;
  d_dnssecOk=false;
  d_havetsig = mdp.getTSIGPos();
  d_haveednssubnet = false;
  d_haveednssection = false;

  if(getEDNSOpts(mdp, &edo)) {
    d_haveednssection=true;
    /* rfc6891 6.2.3:
       "Values lower than 512 MUST be treated as equal to 512."
    */
    d_ednsRawPacketSizeLimit=edo.d_packetsize;
    d_maxreplylen=std::min(std::max(static_cast<uint16_t>(512), edo.d_packetsize), s_udpTruncationThreshold);
//    cerr<<edo.d_extFlags<<endl;
    if(edo.d_extFlags & EDNSOpts::DNSSECOK)
      d_dnssecOk=true;

    for(vector<pair<uint16_t, string> >::const_iterator iter = edo.d_options.begin();
        iter != edo.d_options.end(); 
        ++iter) {
      if(iter->first == EDNSOptionCode::NSID) {
        d_wantsnsid=true;
      }
      else if(s_doEDNSSubnetProcessing && (iter->first == EDNSOptionCode::ECS)) { // 'EDNS SUBNET'
        if(getEDNSSubnetOptsFromString(iter->second, &d_eso)) {
          //cerr<<"Parsed, source: "<<d_eso.source.toString()<<", scope: "<<d_eso.scope.toString()<<", family = "<<d_eso.scope.getNetwork().sin4.sin_family<<endl;
          d_haveednssubnet=true;
        } 
      }
      else {
        // cerr<<"Have an option #"<<iter->first<<": "<<makeHexDump(iter->second)<<endl;
      }
    }
    d_ednsversion = edo.d_version;
    d_ednsrcode = edo.d_extRCode;
 }
  else  {
    d_maxreplylen=512;
    d_ednsRawPacketSizeLimit=-1;
  }

  memcpy((void *)&d,(const void *)d_rawpacket.c_str(),12);
  qdomain=mdp.d_qname;
  // if(!qdomain.empty()) // strip dot
  //   boost::erase_tail(qdomain, 1);

  if(!ntohs(d.qdcount)) {
    if(!d_tcp) {
      g_log << Logger::Warning << "No question section in packet from " << getRemote() <<", error="<<RCode::to_s(d.rcode)<<endl;
      return -1;
    }
  }
  
  qtype=mdp.d_qtype;
  qclass=mdp.d_qclass;

  d_trc = TSIGRecordContent();

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

bool DNSPacket::hasEDNSSubnet() const
{
  return d_haveednssubnet;
}

bool DNSPacket::hasEDNS() const
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

bool DNSPacket::checkForCorrectTSIG(UeberBackend* B, DNSName* keyname, string* secret, TSIGRecordContent* trc) const
{
  uint16_t tsigPos;

  if (!this->getTSIGDetails(trc, keyname, &tsigPos)) {
    return false;
  }

  TSIGTriplet tt;
  tt.name = *keyname;
  tt.algo = trc->d_algoName;
  if (tt.algo == DNSName("hmac-md5.sig-alg.reg.int"))
    tt.algo = DNSName("hmac-md5");

  string secret64;
  if (tt.algo != DNSName("gss-tsig")) {
    if(!B->getTSIGKey(*keyname, &tt.algo, &secret64)) {
      g_log<<Logger::Error<<"Packet for domain '"<<this->qdomain<<"' denied: can't find TSIG key with name '"<<*keyname<<"' and algorithm '"<<tt.algo<<"'"<<endl;
      return false;
    }
    B64Decode(secret64, *secret);
    tt.secret = *secret;
  }

  bool result;

  try {
    result = validateTSIG(d_rawpacket, tsigPos, tt, *trc, "", trc->d_mac, false);
  }
  catch(const std::runtime_error& err) {
    g_log<<Logger::Error<<"Packet for '"<<this->qdomain<<"' denied: "<<err.what()<<endl;
    return false;
  }

  return result;
}

const DNSName& DNSPacket::getTSIGKeyname() const {
  return d_tsigkeyname;
}
