/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2014  PowerDNS.COM BV

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
#include "packetcache.hh"
#include "utility.hh"
#include "base32.hh"
#include <string>
#include <sys/types.h>
#include <boost/algorithm/string.hpp>
#include <boost/foreach.hpp>
#include "dnssecinfra.hh"
#include "dnsseckeeper.hh"
#include "dns.hh"
#include "dnsbackend.hh"
#include "ueberbackend.hh"
#include "dnspacket.hh"
#include "nameserver.hh"
#include "distributor.hh"
#include "logger.hh"
#include "arguments.hh"
#include "packethandler.hh"
#include "statbag.hh"
#include "resolver.hh"
#include "communicator.hh"
#include "dnsproxy.hh"
#include "version.hh"
#include "common_startup.hh"

#if 0
#undef DLOG
#define DLOG(x) x
#endif 
 
AtomicCounter PacketHandler::s_count;
NetmaskGroup PacketHandler::s_allowNotifyFrom;
extern string s_programname;

enum root_referral {
    NO_ROOT_REFERRAL,
    LEAN_ROOT_REFERRAL,
    FULL_ROOT_REFERRAL
};

PacketHandler::PacketHandler():B(s_programname), d_dk(&B)
{
  ++s_count;
  d_doDNAME=::arg().mustDo("experimental-dname-processing");
  d_doRecursion= ::arg().mustDo("recursor");
  d_logDNSDetails= ::arg().mustDo("log-dns-details");
  d_doIPv6AdditionalProcessing = ::arg().mustDo("do-ipv6-additional-processing");
  d_sendRootReferral = ::arg().mustDo("send-root-referral")
                            ? ( pdns_iequals(::arg()["send-root-referral"], "lean") ? LEAN_ROOT_REFERRAL : FULL_ROOT_REFERRAL )
                            : NO_ROOT_REFERRAL;
  string fname= ::arg()["lua-prequery-script"];
  if(fname.empty())
  {
    d_pdl = NULL;
  }
  else
  {
    d_pdl = new AuthLua(fname);
  }

}

UeberBackend *PacketHandler::getBackend()
{
  return &B;
}

PacketHandler::~PacketHandler()
{
  --s_count;
  DLOG(L<<Logger::Error<<"PacketHandler destructor called - "<<s_count<<" left"<<endl);
}

void PacketHandler::addRootReferral(DNSPacket* r)
{  
  // nobody reads what we output, but it appears to be the magic that shuts some nameservers up
  static const char*ips[]={"198.41.0.4", "192.228.79.201", "192.33.4.12", "199.7.91.13", "192.203.230.10", "192.5.5.241", "192.112.36.4", "128.63.2.53", 
                     "192.36.148.17","192.58.128.30", "193.0.14.129", "199.7.83.42", "202.12.27.33"};
  static char templ[40];
  strncpy(templ,"a.root-servers.net", sizeof(templ) - 1);

  // add . NS records
  DNSResourceRecord rr;
  rr.qtype=QType::NS;
  rr.ttl=518400;
  rr.d_place=DNSResourceRecord::AUTHORITY;
  
  for(char c='a';c<='m';++c) {
    *templ=c;
    rr.content=templ;
    r->addRecord(rr);
  }

  if( d_sendRootReferral == LEAN_ROOT_REFERRAL )
     return;

  // add the additional stuff
  
  rr.ttl=3600000;
  rr.qtype=QType::A;
  rr.d_place=DNSResourceRecord::ADDITIONAL;

  for(char c='a';c<='m';++c) {
    *templ=c;
    rr.qname=templ;
    rr.content=ips[c-'a'];
    r->addRecord(rr);
  }
}

/** This adds DNSKEY records. Returns true if one was added */
bool PacketHandler::addDNSKEY(DNSPacket *p, DNSPacket *r, const SOAData& sd)
{
  DNSResourceRecord rr;
  bool haveOne=false;
  DNSSECPrivateKey dpk;

  DNSSECKeeper::keyset_t keyset = d_dk.getKeys(p->qdomain);
  BOOST_FOREACH(DNSSECKeeper::keyset_t::value_type value, keyset) {
    rr.qtype=QType::DNSKEY;
    rr.ttl=sd.default_ttl;
    rr.qname=p->qdomain;
    rr.content=value.first.getDNSKEY().getZoneRepresentation();
    rr.auth=true;
    r->addRecord(rr);
    haveOne=true;
  }

  if(::arg().mustDo("direct-dnskey")) {
    B.lookup(QType(QType::DNSKEY), p->qdomain, p, sd.domain_id);
    while(B.get(rr)) {
      rr.ttl=sd.default_ttl;
      r->addRecord(rr);
      haveOne=true;
    }
  }

  return haveOne;
}


/** This adds NSEC3PARAM records. Returns true if one was added */
bool PacketHandler::addNSEC3PARAM(DNSPacket *p, DNSPacket *r, const SOAData& sd)
{
  DNSResourceRecord rr;

  NSEC3PARAMRecordContent ns3prc;
  if(d_dk.getNSEC3PARAM(p->qdomain, &ns3prc)) {
    rr.qtype=QType::NSEC3PARAM;
    rr.ttl=sd.default_ttl;
    rr.qname=p->qdomain;
    ns3prc.d_flags = 0; // the NSEC3PARAM 'flag' is defined to always be zero in RFC5155.
    rr.content=ns3prc.getZoneRepresentation(); 
    rr.auth = true;
    r->addRecord(rr);
    return true;
  }
  return false;
}


// This is our chaos class requests handler. Return 1 if content was added, 0 if it wasn't
int PacketHandler::doChaosRequest(DNSPacket *p, DNSPacket *r, string &target)
{
  DNSResourceRecord rr;

  if(p->qtype.getCode()==QType::TXT) {
    if (pdns_iequals(target, "version.pdns") || pdns_iequals(target, "version.bind")) {
      // modes: full, powerdns only, anonymous or custom
      const static string mode=::arg()["version-string"];

      if(mode.empty() || mode=="full")
        rr.content=fullVersionString();
      else if(mode=="powerdns")
        rr.content="Served by PowerDNS - https://www.powerdns.com/";
      else if(mode=="anonymous") {
        r->setRcode(RCode::ServFail);
        return 0;
      }
      else
        rr.content=mode;
    }
    else if (pdns_iequals(target, "id.server")) {
      // modes: disabled, hostname or custom
      const static string id=::arg()["server-id"];

      if (id == "disabled") {
        r->setRcode(RCode::Refused);
        return 0;
      }
      rr.content=id;
    }
    else {
      r->setRcode(RCode::Refused);
      return 0;
    }

    rr.ttl=5;
    rr.qname=target;
    rr.qtype=QType::TXT;
    rr.qclass=QClass::CHAOS;
    r->addRecord(rr);
    return 1;
  }

  r->setRcode(RCode::NotImp);
  return 0;
}

vector<DNSResourceRecord> PacketHandler::getBestReferralNS(DNSPacket *p, SOAData& sd, const string &target)
{
  vector<DNSResourceRecord> ret;
  DNSResourceRecord rr;
  string subdomain(target);
  do {
    if(subdomain == sd.qname) // stop at SOA
      break;
    B.lookup(QType(QType::NS), subdomain, p, sd.domain_id);
    while(B.get(rr)) {
      ret.push_back(rr); // this used to exclude auth NS records for some reason
    }
    if(!ret.empty())
      return ret;
  } while( chopOff( subdomain ) );   // 'www.powerdns.org' -> 'powerdns.org' -> 'org' -> ''
  return ret;
}

vector<DNSResourceRecord> PacketHandler::getBestDNAMESynth(DNSPacket *p, SOAData& sd, string &target)
{
  vector<DNSResourceRecord> ret;
  DNSResourceRecord rr;
  string prefix;
  string subdomain(target);
  do {
    DLOG(L<<"Attempting DNAME lookup for "<<subdomain<<", sd.qname="<<sd.qname<<endl);

    B.lookup(QType(QType::DNAME), subdomain, p, sd.domain_id);
    while(B.get(rr)) {
      ret.push_back(rr);  // put in the original
      rr.qtype = QType::CNAME;
      rr.qname = prefix + rr.qname;
      rr.content = prefix + rr.content;
      rr.auth = 0; // don't sign CNAME
      target= rr.content;
      ret.push_back(rr); 
    }
    if(!ret.empty())
      return ret;
    string::size_type pos = subdomain.find('.');
    if(pos != string::npos)
      prefix+= subdomain.substr(0, pos+1);
    if(subdomain == sd.qname) // stop at SOA
      break;

  } while( chopOff( subdomain ) );   // 'www.powerdns.org' -> 'powerdns.org' -> 'org' -> ''
  return ret;
}


// Return best matching wildcard or next closer name
bool PacketHandler::getBestWildcard(DNSPacket *p, SOAData& sd, const string &target, string &wildcard, vector<DNSResourceRecord>* ret)
{
  ret->clear();
  DNSResourceRecord rr;
  string subdomain(target);
  bool haveSomething=false;

  wildcard=subdomain;
  while( chopOff( subdomain ) && !haveSomething )  {
    if (subdomain.empty()) {
      B.lookup(QType(QType::ANY), "*", p, sd.domain_id); 
    } else {
      B.lookup(QType(QType::ANY), "*."+subdomain, p, sd.domain_id);
    }
    while(B.get(rr)) {
      if(rr.qtype == p->qtype || rr.qtype.getCode() == QType::CNAME || (p->qtype.getCode() == QType::ANY && rr.qtype.getCode() != QType::RRSIG))
        ret->push_back(rr);
      wildcard="*."+subdomain;
      haveSomething=true;
    }

    if ( subdomain == sd.qname || haveSomething ) // stop at SOA or result
      break;

    B.lookup(QType(QType::ANY), subdomain, p, sd.domain_id);
    if (B.get(rr)) {
      DLOG(L<<"No wildcard match, ancestor exists"<<endl);
      while (B.get(rr)) ;
      break;
    }
    wildcard=subdomain;
  }

  return haveSomething;
}

/** dangling is declared true if we were unable to resolve everything */
int PacketHandler::doAdditionalProcessingAndDropAA(DNSPacket *p, DNSPacket *r, const SOAData& soadata, bool retargeted)
{
  DNSResourceRecord rr;
  SOAData sd;
  sd.db=0;

  if(p->qtype.getCode()!=QType::AXFR) { // this packet needs additional processing
    vector<DNSResourceRecord *> arrs=r->getAPRecords();
    if(arrs.empty()) 
      return 1;

    DLOG(L<<Logger::Warning<<"This packet needs additional processing!"<<endl);

    vector<DNSResourceRecord> crrs;

    for(vector<DNSResourceRecord *>::const_iterator i=arrs.begin(); i!=arrs.end(); ++i) 
      crrs.push_back(**i);

    // we now have a copy, push_back on packet might reallocate!
    for(vector<DNSResourceRecord>::const_iterator i=crrs.begin(); i!=crrs.end(); ++i) {
      if(r->d.aa && !i->qname.empty() && i->qtype.getCode()==QType::NS && !B.getSOA(i->qname,sd,p) && !retargeted) { // drop AA in case of non-SOA-level NS answer, except for root referral
        r->setA(false);
        //        i->d_place=DNSResourceRecord::AUTHORITY; // XXX FIXME
      }

      string content = stripDot(i->content);
      if(i->qtype == QType::MX || i->qtype == QType::SRV) {
        string::size_type pos = content.find_first_not_of("0123456789");
        if(pos != string::npos)
          boost::erase_head(content, pos);
        trim_left(content);
      }

      QType qtypes[2];
      qtypes[0]="A"; qtypes[1]="AAAA";
      for(int n=0 ; n < d_doIPv6AdditionalProcessing + 1; ++n) {
        if (i->qtype.getCode()==QType::SRV) {
          vector<string>parts;
          stringtok(parts, content);
          if (parts.size() >= 3) {
            B.lookup(qtypes[n],parts[2],p);
          }
          else
            continue;
        }
        else {
          B.lookup(qtypes[n], content, p);
        }
        while(B.get(rr)) {
          if(rr.domain_id!=i->domain_id && ::arg()["out-of-zone-additional-processing"]=="no") {
            DLOG(L<<Logger::Warning<<"Not including out-of-zone additional processing of "<<i->qname<<" ("<<rr.qname<<")"<<endl);
            continue; // not adding out-of-zone additional data
          }
          if(rr.auth && !endsOn(rr.qname, soadata.qname)) // don't sign out of zone data using the main key 
            rr.auth=false;
          rr.d_place=DNSResourceRecord::ADDITIONAL;
          r->addRecord(rr);
        }
      }
    }
  }
  return 1;
}


void PacketHandler::emitNSEC(const std::string& begin, const std::string& end, const std::string& toNSEC, const SOAData& sd, DNSPacket *r, int mode)
{
  // cerr<<"We should emit '"<<begin<<"' - ('"<<toNSEC<<"') - '"<<end<<"'"<<endl;
  NSECRecordContent nrc;
  nrc.d_set.insert(QType::RRSIG);
  nrc.d_set.insert(QType::NSEC);
  if(pdns_iequals(sd.qname, begin)) {
    nrc.d_set.insert(QType::SOA);
    nrc.d_set.insert(QType::DNSKEY);
  }

  DNSResourceRecord rr;
  B.lookup(QType(QType::ANY), begin, NULL, sd.domain_id);
  while(B.get(rr)) {
    if(rr.qtype.getCode() == QType::NS || rr.auth)
      nrc.d_set.insert(rr.qtype.getCode());
  }

  nrc.d_next=end;

  rr.qname=begin;
  rr.ttl = sd.default_ttl;
  rr.qtype=QType::NSEC;
  rr.content=nrc.getZoneRepresentation();
  rr.d_place = (mode == 5 ) ? DNSResourceRecord::ANSWER: DNSResourceRecord::AUTHORITY;
  rr.auth = true;

  r->addRecord(rr);
}

void emitNSEC3(UeberBackend& B, const NSEC3PARAMRecordContent& ns3prc, const SOAData& sd, const std::string& unhashed, const std::string& begin, const std::string& end, const std::string& toNSEC3, DNSPacket *r, int mode)
{
  // cerr<<"We should emit NSEC3 '"<<toBase32Hex(begin)<<"' - ('"<<toNSEC3<<"') - '"<<toBase32Hex(end)<<"' (unhashed: '"<<unhashed<<"')"<<endl;
  NSEC3RecordContent n3rc;
  n3rc.d_salt=ns3prc.d_salt;
  n3rc.d_flags = ns3prc.d_flags;
  n3rc.d_iterations = ns3prc.d_iterations;
  n3rc.d_algorithm = 1; // SHA1, fixed in PowerDNS for now

  DNSResourceRecord rr;
  if(!unhashed.empty()) {
    B.lookup(QType(QType::ANY), unhashed, NULL, sd.domain_id);
    while(B.get(rr)) {
      if(rr.qtype.getCode() && (rr.qtype.getCode() == QType::NS || rr.auth)) // skip empty non-terminals
        n3rc.d_set.insert(rr.qtype.getCode());
    }

    if (pdns_iequals(sd.qname, unhashed)) {
      n3rc.d_set.insert(QType::SOA);
      n3rc.d_set.insert(QType::NSEC3PARAM);
      n3rc.d_set.insert(QType::DNSKEY);
    }
  }

  if (n3rc.d_set.size() && !(n3rc.d_set.size() == 1 && n3rc.d_set.count(QType::NS)))
    n3rc.d_set.insert(QType::RRSIG);

  n3rc.d_nexthash=end;

  rr.qname=dotConcat(toBase32Hex(begin), sd.qname);
  rr.ttl = sd.default_ttl;
  rr.qtype=QType::NSEC3;
  rr.content=n3rc.getZoneRepresentation();
  rr.d_place = (mode == 5 ) ? DNSResourceRecord::ANSWER: DNSResourceRecord::AUTHORITY;
  rr.auth = true;

  r->addRecord(rr);
}

void PacketHandler::emitNSEC3(const NSEC3PARAMRecordContent& ns3prc, const SOAData& sd, const std::string& unhashed, const std::string& begin, const std::string& end, const std::string& toNSEC3, DNSPacket *r, int mode)
{
  ::emitNSEC3(B, ns3prc, sd, unhashed, begin, end, toNSEC3, r, mode);
  
}

/*
   mode 0 = No Data Responses, QTYPE is not DS
   mode 1 = No Data Responses, QTYPE is DS
   mode 2 = Wildcard No Data Responses
   mode 3 = Wildcard Answer Responses
   mode 4 = Name Error Responses
   mode 5 = Direct NSEC request
*/
void PacketHandler::addNSECX(DNSPacket *p, DNSPacket *r, const string& target, const string& wildcard, const string& auth, int mode)
{
  if(!p->d_dnssecOk && mode != 5)
    return;

  NSEC3PARAMRecordContent ns3rc;
  // cerr<<"Doing NSEC3PARAM lookup for '"<<auth<<"', "<<p->qdomain<<"|"<<p->qtype.getName()<<": ";
  bool narrow;
  if(d_dk.getNSEC3PARAM(auth, &ns3rc, &narrow))  {
    // cerr<<"Present, narrow="<<narrow<<endl;
    if (mode != 5) // no direct NSEC3 please
      addNSEC3(p, r, target, wildcard, auth, ns3rc, narrow, mode);
  }
  else {
    // cerr<<"Not present"<<endl;
    addNSEC(p, r, target, wildcard, auth, mode);
  }
}

static void incrementHash(std::string& raw) // I wonder if this is correct, cmouse? ;-)
{
  if(raw.empty())
    return;
    
  for(string::size_type pos=raw.size(); pos; ) {
    --pos;
    unsigned char c = (unsigned char)raw[pos];
    ++c;
    raw[pos] = (char) c;
    if(c)
      break;
  }
}

static void decrementHash(std::string& raw) // I wonder if this is correct, cmouse? ;-)
{
  if(raw.empty())
    return;
    
  for(string::size_type pos=raw.size(); pos; ) {
    --pos;
    unsigned char c = (unsigned char)raw[pos];
    --c;
    raw[pos] = (char) c;
    if(c != 0xff)
      break;
  }
}


bool getNSEC3Hashes(bool narrow, DNSBackend* db, int id, const std::string& hashed, bool decrement, string& unhashed, string& before, string& after, int mode)
{
  bool ret;
  if(narrow) { // nsec3-narrow
    ret=true;
    before=hashed;
    if(decrement) {
      decrementHash(before);
      unhashed.clear();
    }
    after=hashed;
    incrementHash(after);
  }
  else {
    if (decrement || mode <= 1)
      before.clear();
    else
      before=' ';
    ret=db->getBeforeAndAfterNamesAbsolute(id, toBase32Hex(hashed), unhashed, before, after);
    before=fromBase32Hex(before);
    after=fromBase32Hex(after);
  }
  // cerr<<"rgetNSEC3Hashes: "<<hashed<<", "<<unhashed<<", "<<before<<", "<<after<<endl;
  return ret;
}

void PacketHandler::addNSEC3(DNSPacket *p, DNSPacket *r, const string& target, const string& wildcard, const string& auth, const NSEC3PARAMRecordContent& ns3rc, bool narrow, int mode)
{
  DLOG(L<<"addNSEC3() mode="<<mode<<" auth="<<auth<<" target="<<target<<" wildcard="<<wildcard<<endl);

  SOAData sd;
  if(!B.getSOAUncached(auth, sd)) {
    DLOG(L<<"Could not get SOA for domain");
    return;
  }

  bool doNextcloser = false;
  string unhashed, hashed, before, after;
  string closest;
  DNSResourceRecord rr;

  if (mode == 2 || mode == 3 || mode == 4) {
    closest=wildcard;
    (void) chopOff(closest);
  } else
    closest=target;

  // add matching NSEC3 RR
  if (mode != 3) {
    unhashed=(mode == 0 || mode == 1 || mode == 5) ? target : closest;
    hashed=hashQNameWithSalt(ns3rc.d_iterations, ns3rc.d_salt, unhashed);
    DLOG(L<<"1 hash: "<<toBase32Hex(hashed)<<" "<<unhashed<<endl);

    if(!B.getDirectNSECx(sd.domain_id, hashed, QType(QType::NSEC3), before, rr))
      getNSEC3Hashes(narrow, sd.db, sd.domain_id,  hashed, false, unhashed, before, after, mode);

    if (((mode == 0 && ns3rc.d_flags) ||  mode == 1) && (hashed != before)) {
      DLOG(L<<"No matching NSEC3, do closest (provable) encloser"<<endl);

      bool doBreak = false;
      DNSResourceRecord rr;
      while( chopOff( closest ) && (closest != sd.qname))  { // stop at SOA
        B.lookup(QType(QType::ANY), closest, p, sd.domain_id);
        while(B.get(rr))
          if (rr.auth)
            doBreak = true;
        if(doBreak)
          break;
      }
      doNextcloser = true;
      unhashed=closest;
      hashed=hashQNameWithSalt(ns3rc.d_iterations, ns3rc.d_salt, unhashed);
      DLOG(L<<"1 hash: "<<toBase32Hex(hashed)<<" "<<unhashed<<endl);

      if(!B.getDirectNSECx(sd.domain_id, hashed, QType(QType::NSEC3), before, rr))
        getNSEC3Hashes(narrow, sd.db, sd.domain_id,  hashed, false, unhashed, before, after);
    }

    if (!after.empty()) {
      DLOG(L<<"Done calling for matching, hashed: '"<<toBase32Hex(hashed)<<"' before='"<<toBase32Hex(before)<<"', after='"<<toBase32Hex(after)<<"'"<<endl);
      emitNSEC3(ns3rc, sd, unhashed, before, after, target, r, mode);
    } else if(!before.empty())
      r->addRecord(rr);
  }

  // add covering NSEC3 RR
  if ((mode >= 2 && mode <= 4) || doNextcloser) {
    string next(target);
    do {
      unhashed=next;
    }
    while( chopOff( next ) && !pdns_iequals(next, closest));

    hashed=hashQNameWithSalt(ns3rc.d_iterations, ns3rc.d_salt, unhashed);
    DLOG(L<<"2 hash: "<<toBase32Hex(hashed)<<" "<<unhashed<<endl);
    if(!B.getDirectNSECx(sd.domain_id, hashed, QType(QType::NSEC3), before, rr)) {
      getNSEC3Hashes(narrow, sd.db,sd.domain_id,  hashed, true, unhashed, before, after);
      DLOG(L<<"Done calling for covering, hashed: '"<<toBase32Hex(hashed)<<"' before='"<<toBase32Hex(before)<<"', after='"<<toBase32Hex(after)<<"'"<<endl);
      emitNSEC3( ns3rc, sd, unhashed, before, after, target, r, mode);
    } else if(!before.empty())
      r->addRecord(rr);
  }

  // wildcard denial
  if (mode == 2 || mode == 4) {
    unhashed=dotConcat("*", closest);

    hashed=hashQNameWithSalt(ns3rc.d_iterations, ns3rc.d_salt, unhashed);
    DLOG(L<<"3 hash: "<<toBase32Hex(hashed)<<" "<<unhashed<<endl);

    if(!B.getDirectNSECx(sd.domain_id, hashed, QType(QType::NSEC3), before, rr)) {
      getNSEC3Hashes(narrow, sd.db, sd.domain_id,  hashed, (mode != 2), unhashed, before, after);
      DLOG(L<<"Done calling for '*', hashed: '"<<toBase32Hex(hashed)<<"' before='"<<toBase32Hex(before)<<"', after='"<<toBase32Hex(after)<<"'"<<endl);
      emitNSEC3( ns3rc, sd, unhashed, before, after, target, r, mode);
    } else if(!before.empty())
      r->addRecord(rr);
  }
}

void PacketHandler::addNSEC(DNSPacket *p, DNSPacket *r, const string& target, const string& wildcard, const string& auth, int mode)
{
  DLOG(L<<"addNSEC() mode="<<mode<<" auth="<<auth<<" target="<<target<<" wildcard="<<wildcard<<endl);

  SOAData sd;
  if(!B.getSOAUncached(auth, sd)) {
    DLOG(L<<"Could not get SOA for domain"<<endl);
    return;
  }

  string before,after;
  DNSResourceRecord rr;

  rr.auth=false;
  if(!B.getDirectNSECx(sd.domain_id, toLower(labelReverse(makeRelative(target, auth))), QType(QType::NSEC), before, rr)) {
    sd.db->getBeforeAndAfterNames(sd.domain_id, auth, target, before, after);
    emitNSEC(before, after, target, sd, r, mode);
  } else if(rr.auth) {
    if (mode == 5)
      rr.d_place=DNSResourceRecord::ANSWER;
    r->addRecord(rr);
  }

  if (mode == 2 || mode == 4) {
    // wildcard NO-DATA or wildcard denial
    before.clear();
    string closest(wildcard);
    if (mode == 4) {
      (void) chopOff(closest);
      closest=dotConcat("*", closest);
    }
    rr.auth=false;
    if(!B.getDirectNSECx(sd.domain_id, toLower(labelReverse(makeRelative(closest, auth))), QType(QType::NSEC), before, rr)) {
      sd.db->getBeforeAndAfterNames(sd.domain_id, auth, closest, before, after);
      emitNSEC(before, after, target, sd, r, mode);
    } else if(rr.auth)
      r->addRecord(rr);
  }
  return;
}

/* Semantics:
   
- only one backend owns the SOA of a zone
- only one AXFR per zone at a time - double startTransaction should fail
- backends need to implement transaction semantics


How BindBackend would implement this:
   startTransaction makes a file 
   feedRecord sends everything to that file 
   commitTransaction moves that file atomically over the regular file, and triggers a reload
   rollbackTransaction removes the file


How PostgreSQLBackend would implement this:
   startTransaction starts a sql transaction, which also deletes all records
   feedRecord is an insert statement
   commitTransaction commits the transaction
   rollbackTransaction aborts it

How MySQLBackend would implement this:
   (good question!)
   
*/     

int PacketHandler::trySuperMaster(DNSPacket *p)
{
  if(p->d_tcp)
  {
    // do it right now if the client is TCP
    // rarely happens
    return trySuperMasterSynchronous(p);
  }
  else
  {
    // queue it if the client is on UDP
    Communicator.addTrySuperMasterRequest(p);
    return 0;
  }
}

int PacketHandler::trySuperMasterSynchronous(DNSPacket *p)
{
  Resolver::res_t nsset;
  try {
    Resolver resolver;
    uint32_t theirserial;
    resolver.getSoaSerial(p->getRemote(),p->qdomain, &theirserial);    
    resolver.resolve(p->getRemote(), p->qdomain.c_str(), QType::NS, &nsset);
  }
  catch(ResolverException &re) {
    L<<Logger::Error<<"Error resolving SOA or NS for "<<p->qdomain<<" at: "<< p->getRemote() <<": "<<re.reason<<endl;
    return RCode::ServFail;
  }

  // check if the returned records are NS records
  bool haveNS=false;
  BOOST_FOREACH(const DNSResourceRecord& ns, nsset) {
    if(ns.qtype.getCode()==QType::NS)
      haveNS=true;
  }

  if(!haveNS) {
    L<<Logger::Error<<"While checking for supermaster, did not find NS for "<<p->qdomain<<" at: "<< p->getRemote()<<endl;
    return RCode::ServFail;
  }

  string nameserver, account;
  DNSBackend *db;
  if(!B.superMasterBackend(p->getRemote(), p->qdomain, nsset, &nameserver, &account, &db)) {
    L<<Logger::Error<<"Unable to find backend willing to host "<<p->qdomain<<" for potential supermaster "<<p->getRemote()<<". Remote nameservers: "<<endl;
    BOOST_FOREACH(class DNSResourceRecord& rr, nsset) {
      if(rr.qtype.getCode()==QType::NS)
        L<<Logger::Error<<rr.content<<endl;
    }
    return RCode::Refused;
  }
  try {
    db->createSlaveDomain(p->getRemote(), p->qdomain, nameserver, account);
  }
  catch(PDNSException& ae) {
    L<<Logger::Error<<"Database error trying to create "<<p->qdomain<<" for potential supermaster "<<p->getRemote()<<": "<<ae.reason<<endl;
    return RCode::ServFail;
  }
  L<<Logger::Warning<<"Created new slave zone '"<<p->qdomain<<"' from supermaster "<<p->getRemote()<<endl;
  return RCode::NoError;
}

int PacketHandler::processNotify(DNSPacket *p)
{
  /* now what? 
     was this notification from an approved address?
     We determine our internal SOA id (via UeberBackend)
     We determine the SOA at our (known) master
     if master is higher -> do stuff
  */
  if(!::arg().mustDo("slave")) {
    L<<Logger::Error<<"Received NOTIFY for "<<p->qdomain<<" from "<<p->getRemote()<<" but slave support is disabled in the configuration"<<endl;
    return RCode::NotImp;
  }

  if(!s_allowNotifyFrom.match((ComboAddress *) &p->d_remote )) {
    L<<Logger::Notice<<"Received NOTIFY for "<<p->qdomain<<" from "<<p->getRemote()<<" but remote is not in allow-notify-from"<<endl;
    return RCode::Refused;
  }

  DNSBackend *db=0;
  DomainInfo di;
  di.serial = 0;
  if(!B.getDomainInfo(p->qdomain, di) || !(db=di.backend)) {
    L<<Logger::Error<<"Received NOTIFY for "<<p->qdomain<<" from "<<p->getRemote()<<" for which we are not authoritative"<<endl;
    return trySuperMaster(p);
  }
    
  if(::arg().contains("trusted-notification-proxy", p->getRemote())) {
    L<<Logger::Error<<"Received NOTIFY for "<<p->qdomain<<" from trusted-notification-proxy "<< p->getRemote()<<endl;
    if(di.masters.empty()) {
      L<<Logger::Error<<"However, "<<p->qdomain<<" does not have any masters defined"<<endl;
      return RCode::Refused;
    }
  }
  else if(!db->isMaster(p->qdomain, p->getRemote())) {
    L<<Logger::Error<<"Received NOTIFY for "<<p->qdomain<<" from "<<p->getRemote()<<" which is not a master"<<endl;
    return RCode::Refused;
  }
    
  // ok, we've done our checks
  di.backend = 0;
  Communicator.addSlaveCheckRequest(di, p->d_remote);
  return 0;
}

bool validDNSName(const string &name)
{
  string::size_type pos, length=name.length();
  char c;
  for(pos=0; pos < length; ++pos) {
    c=name[pos];
    if(!((c >= 'a' && c <= 'z') ||
         (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9') ||
         c =='-' || c == '_' || c=='*' || c=='.' || c=='/' || c=='@' || c==' ' || c=='\\' || c==':'))
      return false;
  }
  return true;
}  

DNSPacket *PacketHandler::question(DNSPacket *p)
{
  DNSPacket *ret;
  int policyres = PolicyDecision::PASS;

  if(d_pdl)
  {
    ret=d_pdl->prequery(p);
    if(ret)
      return ret;
  }

  if(p->d.rd) {
    static AtomicCounter &rdqueries=*S.getPointer("rd-queries");  
    rdqueries++;
  }

  if(LPE)
  {
    policyres = LPE->police(p, NULL);
  }

  if (policyres == PolicyDecision::DROP)
    return NULL;

  if (policyres == PolicyDecision::TRUNCATE) {
    ret=p->replyPacket();  // generate an empty reply packet
    ret->d.tc = 1;
    ret->commitD();
    return ret;
  }

  bool shouldRecurse=false;
  ret=questionOrRecurse(p, &shouldRecurse);
  if(shouldRecurse) {
    DP->sendPacket(p);
  }
  if(LPE) {
    int policyres=LPE->police(p, ret);
    if(policyres == PolicyDecision::DROP) {
      delete ret;
      return NULL;
    }
    if (policyres == PolicyDecision::TRUNCATE) {
      delete ret;
      ret=p->replyPacket();  // generate an empty reply packet
      ret->d.tc = 1;
      ret->commitD();
    }

  }
  return ret;
}

void PacketHandler::makeNXDomain(DNSPacket* p, DNSPacket* r, const std::string& target, const std::string& wildcard, SOAData& sd)
{
  DNSResourceRecord rr;
  rr.qname=sd.qname;
  rr.qtype=QType::SOA;
  rr.content=serializeSOAData(sd);
  rr.ttl=min(sd.ttl, sd.default_ttl);
  rr.signttl=sd.ttl;
  rr.domain_id=sd.domain_id;
  rr.d_place=DNSResourceRecord::AUTHORITY;
  rr.auth = 1;
  rr.scopeMask = sd.scopeMask;
  r->addRecord(rr);

  if(d_dk.isSecuredZone(sd.qname))
    addNSECX(p, r, target, wildcard, sd.qname, 4);

  r->setRcode(RCode::NXDomain);
}

void PacketHandler::makeNOError(DNSPacket* p, DNSPacket* r, const std::string& target, const std::string& wildcard, SOAData& sd, int mode)
{
  DNSResourceRecord rr;
  rr.qname=sd.qname;
  rr.qtype=QType::SOA;
  rr.content=serializeSOAData(sd);
  rr.ttl=sd.ttl;
  rr.ttl=min(sd.ttl, sd.default_ttl);
  rr.signttl=sd.ttl;
  rr.domain_id=sd.domain_id;
  rr.d_place=DNSResourceRecord::AUTHORITY;
  rr.auth = 1;
  r->addRecord(rr);

  if(d_dk.isSecuredZone(sd.qname))
    addNSECX(p, r, target, wildcard, sd.qname, mode);

  S.ringAccount("noerror-queries",p->qdomain+"/"+p->qtype.getName());
}


bool PacketHandler::addDSforNS(DNSPacket* p, DNSPacket* r, SOAData& sd, const string& dsname)
{
  //cerr<<"Trying to find a DS for '"<<dsname<<"', domain_id = "<<sd.domain_id<<endl;
  B.lookup(QType(QType::DS), dsname, p, sd.domain_id);
  DNSResourceRecord rr;
  bool gotOne=false;
  while(B.get(rr)) {
    gotOne=true;
    rr.d_place = DNSResourceRecord::AUTHORITY;
    r->addRecord(rr);
  }
  return gotOne;
}

bool PacketHandler::tryReferral(DNSPacket *p, DNSPacket*r, SOAData& sd, const string &target, bool retargeted)
{
  vector<DNSResourceRecord> rrset = getBestReferralNS(p, sd, target);
  if(rrset.empty())
    return false;
  
  DLOG(L<<"The best NS is: "<<rrset.begin()->qname<<endl);
  BOOST_FOREACH(DNSResourceRecord rr, rrset) {
    DLOG(L<<"\tadding '"<<rr.content<<"'"<<endl);
    rr.d_place=DNSResourceRecord::AUTHORITY;
    r->addRecord(rr);
  }
  if(!retargeted)
    r->setA(false);

  if(d_dk.isSecuredZone(sd.qname) && !addDSforNS(p, r, sd, rrset.begin()->qname))
    addNSECX(p, r, rrset.begin()->qname, "", sd.qname, 1);
  
  return true;
}

void PacketHandler::completeANYRecords(DNSPacket *p, DNSPacket*r, SOAData& sd, const string &target)
{
  if(!p->d_dnssecOk)
    return; // Don't send dnssec info to non validating resolvers.

  if(!d_dk.isSecuredZone(sd.qname))
    return;
    
  addNSECX(p, r, target, "", sd.qname, 5);
  if(pdns_iequals(sd.qname, p->qdomain)) {
    addDNSKEY(p, r, sd);
    addNSEC3PARAM(p, r, sd);
  }
}

bool PacketHandler::tryDNAME(DNSPacket *p, DNSPacket*r, SOAData& sd, string &target)
{
  if(!d_doDNAME)
    return false;
  DLOG(L<<Logger::Warning<<"Let's try DNAME.."<<endl);
  vector<DNSResourceRecord> rrset = getBestDNAMESynth(p, sd, target);
  if(!rrset.empty()) {
    BOOST_FOREACH(DNSResourceRecord& rr, rrset) {
      rr.d_place = DNSResourceRecord::ANSWER;
      r->addRecord(rr);
    }
    return true;
  }
  return false;
}
bool PacketHandler::tryWildcard(DNSPacket *p, DNSPacket*r, SOAData& sd, string &target, string &wildcard, bool& retargeted, bool& nodata)
{
  retargeted = nodata = false;
  string bestmatch;

  vector<DNSResourceRecord> rrset;
  if(!getBestWildcard(p, sd, target, wildcard, &rrset))
    return false;

  if(rrset.empty()) {
    DLOG(L<<"Wildcard matched something, but not of the correct type"<<endl);
    nodata=true;
  }
  else {
    DLOG(L<<"The best wildcard match: "<<rrset.begin()->qname<<endl);
    BOOST_FOREACH(DNSResourceRecord rr, rrset) {
      rr.wildcardname = rr.qname;
      rr.qname=bestmatch=target;

      if(rr.qtype.getCode() == QType::CNAME)  {
        retargeted=true;
        target=rr.content;
      }
  
      DLOG(L<<"\tadding '"<<rr.content<<"'"<<endl);
      rr.d_place=DNSResourceRecord::ANSWER;
      r->addRecord(rr);
    }
  }
  if(d_dk.isSecuredZone(sd.qname) && !nodata) {
    addNSECX(p, r, bestmatch, wildcard, sd.qname, 3);
  }
  return true;
}

//! Called by the Distributor to ask a question. Returns 0 in case of an error
DNSPacket *PacketHandler::questionOrRecurse(DNSPacket *p, bool *shouldRecurse)
{
  *shouldRecurse=false;
  DNSResourceRecord rr;
  SOAData sd;

  string subdomain="";
  string soa;
  int retargetcount=0;
  set<string, CIStringCompare> authSet;

  vector<DNSResourceRecord> rrset;
  bool weDone=0, weRedirected=0, weHaveUnauth=0;
  string haveAlias;

  DNSPacket *r=0;
  bool noCache=false;
  
  if(p->d.qr) { // QR bit from dns packet (thanks RA from N)
    L<<Logger::Error<<"Received an answer (non-query) packet from "<<p->getRemote()<<", dropping"<<endl;
    S.inc("corrupt-packets");
    S.ringAccount("remotes-corrupt", p->d_remote);
    return 0;
  }

  if(p->d_havetsig) {
    string keyname, secret;
    TSIGRecordContent trc;
    if(!checkForCorrectTSIG(p, &B, &keyname, &secret, &trc)) {
      r=p->replyPacket();  // generate an empty reply packet
      if(d_logDNSDetails)
        L<<Logger::Error<<"Received a TSIG signed message with a non-validating key"<<endl;
      // RFC3007 describes that a non-secure message should be sending Refused for DNS Updates
      if (p->d.opcode == Opcode::Update)
        r->setRcode(RCode::Refused);
      else
        r->setRcode(RCode::NotAuth);
      return r;
    }
    p->setTSIGDetails(trc, keyname, secret, trc.d_mac); // this will get copied by replyPacket()
    noCache=true;
  }
  
  r=p->replyPacket();  // generate an empty reply packet, possibly with TSIG details inside

  if (p->qtype == QType::TKEY) {
    this->tkeyHandler(p, r);
    return r;
  }

  try {    

    // XXX FIXME do this in DNSPacket::parse ?

    if(!validDNSName(p->qdomain)) {
      if(d_logDNSDetails)
        L<<Logger::Error<<"Received a malformed qdomain from "<<p->getRemote()<<", '"<<p->qdomain<<"': sending servfail"<<endl;
      S.inc("corrupt-packets");
      S.ringAccount("remotes-corrupt", p->d_remote);
      S.inc("servfail-packets");
      r->setRcode(RCode::ServFail);
      return r;
    }
    if(p->d.opcode) { // non-zero opcode (again thanks RA!)
      if(p->d.opcode==Opcode::Update) {
        S.inc("dnsupdate-queries");
        int res=processUpdate(p);
        if (res == RCode::Refused)
          S.inc("dnsupdate-refused");
        else if (res != RCode::ServFail)
          S.inc("dnsupdate-answers");
        r->setRcode(res);
        r->setOpcode(Opcode::Update);
        return r;
      }
      else if(p->d.opcode==Opcode::Notify) {
        S.inc("incoming-notifications");
        int res=processNotify(p);
        if(res>=0) {
          r->setRcode(res);
          r->setOpcode(Opcode::Notify);
          return r;
        }
        delete r;
        return 0;
      }
      
      L<<Logger::Error<<"Received an unknown opcode "<<p->d.opcode<<" from "<<p->getRemote()<<" for "<<p->qdomain<<endl;

      r->setRcode(RCode::NotImp); 
      return r; 
    }

    // L<<Logger::Warning<<"Query for '"<<p->qdomain<<"' "<<p->qtype.getName()<<" from "<<p->getRemote()<< " (tcp="<<p->d_tcp<<")"<<endl;
    
    r->d.ra = (p->d.rd && d_doRecursion && DP->recurseFor(p));  // make sure we set ra if rd was set, and we'll do it

    if(p->qtype.getCode()==QType::IXFR) {
      r->setRcode(RCode::NotImp);
      return r;
    }

    string target=p->qdomain;

    // catch chaos qclass requests
    if(p->qclass == QClass::CHAOS) {
      if (doChaosRequest(p,r,target))
        goto sendit;
      else
        return r;
    }

    // we only know about qclass IN (and ANY), send NotImp for everything else.
    if(p->qclass != QClass::IN && p->qclass!=QClass::ANY) {
      r->setRcode(RCode::NotImp);
      return r;
    }

    // send TC for udp ANY query if any-to-tcp is enabled.
    if(p->qtype.getCode() == QType::ANY && !p->d_tcp && g_anyToTcp) {
      r->d.tc = 1;
      r->commitD();
      return r;
    }

    // for qclass ANY the response should never be authoritative unless the response covers all classes.
    if(p->qclass==QClass::ANY)
      r->setA(false);


  retargeted:;
    if(retargetcount > 10) {    // XXX FIXME, retargetcount++?
      L<<Logger::Warning<<"Abort CNAME chain resolution after "<<--retargetcount<<" redirects, sending out servfail. Initial query: '"<<p->qdomain<<"'"<<endl;
      delete r;
      r=p->replyPacket();
      r->setRcode(RCode::ServFail);
      return r;
    }
    
    if(!B.getAuth(p, &sd, target)) {
      DLOG(L<<Logger::Error<<"We have no authority over zone '"<<target<<"'"<<endl);
      if(r->d.ra) {
        DLOG(L<<Logger::Error<<"Recursion is available for this remote, doing that"<<endl);
        *shouldRecurse=true;
        delete r;
        return 0;
      }
      
      if(!retargetcount)
        r->setA(false); // drop AA if we never had a SOA in the first place
      if( d_sendRootReferral != NO_ROOT_REFERRAL ) {
        DLOG(L<<Logger::Warning<<"Adding root-referral"<<endl);
        addRootReferral(r);
      }
      else {
        if (!retargetcount)
          r->setRcode(RCode::Refused); // send REFUSED - but only on empty 'no idea'
      }
      goto sendit;
    }
    DLOG(L<<Logger::Error<<"We have authority, zone='"<<sd.qname<<"', id="<<sd.domain_id<<endl);
    authSet.insert(sd.qname); 

    if(!retargetcount) r->qdomainzone=sd.qname;


    if(pdns_iequals(sd.qname, p->qdomain)) {
      if(p->qtype.getCode() == QType::DNSKEY)
      {
        if(addDNSKEY(p, r, sd))
          goto sendit;
      }
      else if(p->qtype.getCode() == QType::NSEC3PARAM)
      {
        if(addNSEC3PARAM(p,r, sd))
          goto sendit;
      }
    }

    if(p->qtype.getCode() == QType::SOA && pdns_iequals(sd.qname, p->qdomain)) {
      rr.qname=sd.qname;
      rr.qtype=QType::SOA;
      rr.content=serializeSOAData(sd);
      rr.ttl=sd.ttl;
      rr.domain_id=sd.domain_id;
      rr.d_place=DNSResourceRecord::ANSWER;
      rr.auth = true;
      r->addRecord(rr);
      goto sendit;
    }

    // this TRUMPS a cname!
    if(p->qtype.getCode() == QType::NSEC && d_dk.isSecuredZone(sd.qname) && !d_dk.getNSEC3PARAM(sd.qname, 0)) {
      addNSEC(p, r, target, "", sd.qname, 5);
      goto sendit;
    }

    // this TRUMPS a cname!
    if(p->qtype.getCode() == QType::RRSIG) {
      L<<Logger::Info<<"Direct RRSIG query for "<<target<<" from "<<p->getRemote()<<endl;
      r->setRcode(RCode::NotImp);
      goto sendit;
    }

    DLOG(L<<"Checking for referrals first, unless this is a DS query"<<endl);
    if(p->qtype.getCode() != QType::DS && tryReferral(p, r, sd, target, retargetcount))
      goto sendit;

    DLOG(L<<"Got no referrals, trying ANY"<<endl);

    // see what we get..
    B.lookup(QType(QType::ANY), target, p, sd.domain_id);
    rrset.clear();
    haveAlias.clear();
    weDone = weRedirected = weHaveUnauth =  false;
    
    while(B.get(rr)) {
      if (p->qtype.getCode() == QType::ANY && !p->d_dnssecOk && (rr.qtype.getCode() == QType:: DNSKEY || rr.qtype.getCode() == QType::NSEC3PARAM))
        continue; // Don't send dnssec info to non validating resolvers.
      if (rr.qtype.getCode() == QType::RRSIG) // RRSIGS are added later any way.
        continue; // TODO: this actually means addRRSig should check if the RRSig is already there

      // cerr<<"Auth: "<<rr.auth<<", "<<(rr.qtype == p->qtype)<<", "<<rr.qtype.getName()<<endl;
      if((p->qtype.getCode() == QType::ANY || rr.qtype == p->qtype) && rr.auth) 
        weDone=1;
      // the line below fakes 'unauth NS' for delegations for non-DNSSEC backends.
      if((rr.qtype == p->qtype && !rr.auth) || (rr.qtype.getCode() == QType::NS && (!rr.auth || !pdns_iequals(sd.qname, rr.qname))))
        weHaveUnauth=1;

      if(rr.qtype.getCode() == QType::CNAME && p->qtype.getCode() != QType::CNAME) 
        weRedirected=1;

      if(DP && rr.qtype.getCode() == QType::ALIAS) {
	haveAlias=rr.content;
      }

      // Filter out all SOA's and add them in later
      if(rr.qtype.getCode() == QType::SOA)
        continue;

      rrset.push_back(rr);
    }

    /* Add in SOA if required */
    if( pdns_iequals( target, sd.qname ) ) {
        rr.qtype = QType::SOA;
        rr.content = serializeSOAData(sd);
        rr.qname = sd.qname;
        rr.ttl = sd.ttl;
        rr.domain_id = sd.domain_id;
        rr.auth = true;
        rrset.push_back(rr);
    }


    DLOG(L<<"After first ANY query for '"<<target<<"', id="<<sd.domain_id<<": weDone="<<weDone<<", weHaveUnauth="<<weHaveUnauth<<", weRedirected="<<weRedirected<<", haveAlias='"<<haveAlias<<"'"<<endl);
    if(p->qtype.getCode() == QType::DS && weHaveUnauth &&  !weDone && !weRedirected && d_dk.isSecuredZone(sd.qname)) {
      DLOG(L<<"Q for DS of a name for which we do have NS, but for which we don't have on a zone with DNSSEC need to provide an AUTH answer that proves we don't"<<endl);
      makeNOError(p, r, target, "", sd, 1);
      goto sendit;
    }

    if(!haveAlias.empty() && !weDone) {
      DLOG(L<<Logger::Warning<<"Found nothing that matched for '"<<target<<"', but did get alias to '"<<haveAlias<<"', referring"<<endl);
      DP->completePacket(r, haveAlias, target);
      return 0;
    }

    if(rrset.empty()) {
      DLOG(L<<"checking qtype.getCode() ["<<(p->qtype.getCode())<<"] against QType::DS ["<<(QType::DS)<<"]"<<endl);
      if(p->qtype.getCode() == QType::DS)
      {
        DLOG(L<<"DS query found no direct result, trying referral now"<<endl);
        if(tryReferral(p, r, sd, target, retargetcount))
        {
          DLOG(L<<"got referral for DS query"<<endl);
          goto sendit;
        }
      }


      DLOG(L<<Logger::Warning<<"Found nothing in the by-name ANY, but let's try wildcards.."<<endl);
      bool wereRetargeted(false), nodata(false);
      string wildcard;
      if(tryWildcard(p, r, sd, target, wildcard, wereRetargeted, nodata)) {
        if(wereRetargeted) {
          if(!retargetcount) r->qdomainwild=wildcard;
          retargetcount++;
          goto retargeted;
        }
        if(nodata) 
          makeNOError(p, r, target, wildcard, sd, 2);

        goto sendit;
      }
      else if(tryDNAME(p, r, sd, target)) {
	retargetcount++;
	goto retargeted;
      }
      else
      {        
        if (!(((p->qtype.getCode() == QType::CNAME) || (p->qtype.getCode() == QType::ANY)) && retargetcount > 0))
          makeNXDomain(p, r, target, wildcard, sd);
      }
      
      goto sendit;
    }
                                       
    if(weRedirected) {
      BOOST_FOREACH(rr, rrset) {
        if(rr.qtype.getCode() == QType::CNAME) {
          r->addRecord(rr);
          target = rr.content;
          retargetcount++;
          goto retargeted;
        }
      }
    }
    else if(weDone) {
      bool haveRecords = false;
      BOOST_FOREACH(rr, rrset) {
        if((p->qtype.getCode() == QType::ANY || rr.qtype == p->qtype) && rr.qtype.getCode() && rr.auth) {
          r->addRecord(rr);
          haveRecords = true;
        }
      }

      if (haveRecords) {
        if(p->qtype.getCode() == QType::ANY)
          completeANYRecords(p, r, sd, target);
      }
      else
        makeNOError(p, r, rr.qname, "", sd, 0);

      goto sendit;
    }
    else if(weHaveUnauth) {
      DLOG(L<<"Have unauth data, so need to hunt for best NS records"<<endl);
      if(tryReferral(p, r, sd, target, retargetcount))
        goto sendit;
      // check whether this could be fixed easily
      if (*(rr.qname.rbegin()) == '.') {
           L<<Logger::Error<<"Should not get here ("<<p->qdomain<<"|"<<p->qtype.getCode()<<"): you have a trailing dot, this could be the problem (or run pdnssec rectify-zone " <<sd.qname<<")"<<endl;
      } else {
           L<<Logger::Error<<"Should not get here ("<<p->qdomain<<"|"<<p->qtype.getCode()<<"): please run pdnssec rectify-zone "<<sd.qname<<endl;
      }
    }
    else {
      DLOG(L<<"Have some data, but not the right data"<<endl);
      makeNOError(p, r, target, "", sd, 0);
    }
    
  sendit:;
    if(doAdditionalProcessingAndDropAA(p, r, sd, retargetcount)<0) {
      delete r;
      return 0;
    }

    editSOA(d_dk, sd.qname, r);
    
    BOOST_FOREACH(const DNSResourceRecord& rr, r->getRRS()) {
      if(rr.scopeMask) {
        noCache=1;
        break;
      }
    }
    if(p->d_dnssecOk)
      addRRSigs(d_dk, B, authSet, r->getRRS());
      
    r->wrapup(); // needed for inserting in cache
    if(!noCache)
      PC.insert(p, r, false, r->getMinTTL()); // in the packet cache
  }
  catch(DBException &e) {
    L<<Logger::Error<<"Backend reported condition which prevented lookup ("+e.reason+") sending out servfail"<<endl;
    delete r;
    r=p->replyPacket(); // generate an empty reply packet
    r->setRcode(RCode::ServFail);
    S.inc("servfail-packets");
    S.ringAccount("servfail-queries",p->qdomain);
  }
  catch(PDNSException &e) {
    L<<Logger::Error<<"Backend reported permanent error which prevented lookup ("+e.reason+"), aborting"<<endl;
    throw; // we WANT to die at this point
  }
  catch(std::exception &e) {
    L<<Logger::Error<<"Exception building answer packet ("<<e.what()<<") sending out servfail"<<endl;
    delete r;
    r=p->replyPacket(); // generate an empty reply packet
    r->setRcode(RCode::ServFail);
    S.inc("servfail-packets");
    S.ringAccount("servfail-queries",p->qdomain);
  }
  return r; 

}

void PacketHandler::tkeyHandler(DNSPacket *p, DNSPacket *r) {
  TKEYRecordContent tkey_in;
  boost::shared_ptr<TKEYRecordContent> tkey_out(new TKEYRecordContent());
  string label, lcLabel;

  if (!p->getTKEYRecord(&tkey_in, &label)) {
    L<<Logger::Error<<"TKEY request but no TKEY RR found"<<endl;
    r->setRcode(RCode::FormErr);
    return;
  }

  // retain original label for response
  lcLabel = toLowerCanonic(label);

  tkey_out->d_error = 0;
  tkey_out->d_mode = tkey_in.d_mode;
  tkey_out->d_algo = tkey_in.d_algo;
  tkey_out->d_inception = time((time_t*)NULL);
  tkey_out->d_expiration = tkey_out->d_inception+15;

  if (tkey_in.d_mode == 3) {
    tkey_out->d_error = 19; // BADMODE
  } else if (tkey_in.d_mode == 5) {
    if (p->d_havetsig == false) { // unauthenticated
      if (p->d.opcode == Opcode::Update)
        r->setRcode(RCode::Refused);
      else
        r->setRcode(RCode::NotAuth);
      return;
    }
    tkey_out->d_error = 20; // BADNAME (because we have no support for anything here)
  } else {
    if (p->d_havetsig == false && tkey_in.d_mode != 2) { // unauthenticated
      if (p->d.opcode == Opcode::Update)
        r->setRcode(RCode::Refused);
      else
        r->setRcode(RCode::NotAuth);
      return;
    }
    tkey_out->d_error = 19; // BADMODE
  }

  tkey_out->d_keysize = tkey_out->d_key.size();
  tkey_out->d_othersize = tkey_out->d_other.size();

  DNSRecord rec;
  rec.d_label = label;
  rec.d_ttl = 0;
  rec.d_type = QType::TKEY;
  rec.d_class = QClass::ANY;
  rec.d_content = tkey_out;

  DNSResourceRecord rr(rec);
  rr.qclass = QClass::ANY;
  rr.qtype = QType::TKEY;
  rr.d_place = DNSResourceRecord::ANSWER;
  r->addRecord(rr);
  r->commitD();
}
