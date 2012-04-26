/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2012  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

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

#if 0
#undef DLOG
#define DLOG(x) x
#endif 

extern StatBag S;
extern PacketCache PC;  
extern CommunicatorClass Communicator;
extern DNSProxy *DP;

AtomicCounter PacketHandler::s_count;
extern string s_programname;

PacketHandler::PacketHandler():B(s_programname)
{
  ++s_count;
  d_doFancyRecords = (::arg()["fancy-records"]!="no");
  d_doRecursion= ::arg().mustDo("recursor");
  d_logDNSDetails= ::arg().mustDo("log-dns-details");
  d_doIPv6AdditionalProcessing = ::arg().mustDo("do-ipv6-additional-processing");
}

DNSBackend *PacketHandler::getBackend()
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
  static const char*ips[]={"198.41.0.4", "192.228.79.201", "192.33.4.12", "128.8.10.90", "192.203.230.10", "192.5.5.241", "192.112.36.4", "128.63.2.53", 
        	     "192.36.148.17","192.58.128.30", "193.0.14.129", "198.32.64.12", "202.12.27.33"};
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

  if(pdns_iequals(::arg()["send-root-referral"], "lean"))
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

int PacketHandler::findMboxFW(DNSPacket *p, DNSPacket *r, string &target)
{
  DNSResourceRecord rr;
  bool wedoforward=false;

  SOAData sd;
  int zoneId;
  if(!getAuth(p, &sd, target, &zoneId))
    return false;

  B.lookup(QType(QType::MBOXFW),string("%@")+target,p, zoneId);
      
  while(B.get(rr))
    wedoforward=true;

  if(wedoforward) {
    r->clearRecords();
    rr.content=::arg()["smtpredirector"];
    rr.priority=25;
    rr.ttl=7200;
    rr.qtype=QType::MX;
    rr.qname=target;
    
    r->addRecord(rr);
  }

  return wedoforward;
}

int PacketHandler::findUrl(DNSPacket *p, DNSPacket *r, string &target)
{
  DNSResourceRecord rr;

  bool found=false;
      
  B.lookup(QType(QType::URL),target,p); // search for a URL before we search for an A
        
  while(B.get(rr)) {
    if(!found) 
      r->clearRecords();
    found=true;
    DLOG(L << "Found a URL!" << endl);
    rr.content=::arg()["urlredirector"];
    rr.qtype=QType::A; 
    rr.qname=target;
          
    r->addRecord(rr);
  }  

  if(found) 
    return 1;

  // now try CURL
  
  B.lookup(QType(QType::CURL),target,p); // search for a URL before we search for an A
      
  while(B.get(rr)) {
    if(!found) 
      r->clearRecords();
    found=true;
    DLOG(L << "Found a CURL!" << endl);
    rr.content=::arg()["urlredirector"];
    rr.qtype=1; // A
    rr.qname=target;
    rr.ttl=300;
    r->addRecord(rr);
  }  

  if(found)
    return found;
  return 0;
}

/** Returns 0 if nothing was found, -1 if an error occured or 1 if the search
    was satisfied */
int PacketHandler::doFancyRecords(DNSPacket *p, DNSPacket *r, string &target)
{
  DNSResourceRecord rr;
  if(p->qtype.getCode()==QType::MX)  // check if this domain has smtp service from us
    return findMboxFW(p,r,target);
  
  if(p->qtype.getCode()==QType::A)   // search for a URL record for an A
    return findUrl(p,r,target);
  return 0;
}

/** This catches DNSKEY requests. Returns 1 if it was handled, 0 if it wasn't */
int PacketHandler::doDNSKEYRequest(DNSPacket *p, DNSPacket *r, const SOAData& sd)
{
  if(p->qtype.getCode()!=QType::DNSKEY) 
    return false;
    
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
  return haveOne;
}


/** This catches DNSKEY requests. Returns 1 if it was handled, 0 if it wasn't */
int PacketHandler::doNSEC3PARAMRequest(DNSPacket *p, DNSPacket *r, const SOAData& sd)
{
  if(p->qtype.getCode()!=QType::NSEC3PARAM) 
    return false;

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


/** This catches version requests. Returns 1 if it was handled, 0 if it wasn't */
int PacketHandler::doVersionRequest(DNSPacket *p, DNSPacket *r, string &target)
{
  DNSResourceRecord rr;
  
  // modes: anonymous, powerdns only, full, spoofed
  const string mode=::arg()["version-string"];
  
  if(p->qclass == QClass::CHAOS && p->qtype.getCode()==QType::TXT && target=="version.bind") {// TXT
    if(mode.empty() || mode=="full") 
      rr.content="Served by POWERDNS "VERSION" $Id$";
    else if(mode=="anonymous") {
      r->setRcode(RCode::ServFail);
      return 1;
    }
    else if(mode=="powerdns")
      rr.content="Served by PowerDNS - http://www.powerdns.com";
    else 
      rr.content=mode;

    rr.ttl=5;
    rr.qname=target;
    rr.qtype=QType::TXT; 
    rr.qclass=QClass::CHAOS; 
    r->addRecord(rr);
    
    return 1;
  }
  return 0;
}

/** Determines if we are authoritative for a zone, and at what level */
bool PacketHandler::getAuth(DNSPacket *p, SOAData *sd, const string &target, int *zoneId)
{
  string subdomain(target);
  do {
    if( B.getSOA( subdomain, *sd, p ) ) {
      if(p->qtype.getCode() == QType::DS && pdns_iequals(subdomain, target)) 
        continue; // A DS question is never answered from the apex, go one zone upwards 
      
      sd->qname = subdomain;
      if(zoneId)
        *zoneId = sd->domain_id;
      return true;
    }
  }
  while( chopOff( subdomain ) );   // 'www.powerdns.org' -> 'powerdns.org' -> 'org' -> ''
  return false;
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

bool PacketHandler::getBestWildcard(DNSPacket *p, SOAData& sd, const string &target, vector<DNSResourceRecord>* ret)
{
  ret->clear();
  DNSResourceRecord rr;
  string subdomain(target);
  while( chopOff( subdomain ))  {
    B.lookup(QType(QType::ANY), "*."+subdomain, p, sd.domain_id);
    bool haveSomething=false;
    while(B.get(rr)) {
      if(rr.qtype == p->qtype ||rr.qtype.getCode() == QType::CNAME || p->qtype.getCode() == QType::ANY)
        ret->push_back(rr);
      haveSomething=true;
    }
    
    if(haveSomething)
      return true;
    
    if(subdomain == sd.qname) // stop at SOA
      break;
  } 

  return false;
}


/** returns 1 in case of a straight match, 2 in case of a wildcard CNAME (groan), 0 in case of no hit */
int PacketHandler::doWildcardRecords(DNSPacket *p, DNSPacket *r, string &target)
{
  DNSResourceRecord rr;
  bool found=false, retargeted=false;

  // try chopping off domains and look for wildcard matches

  // *.pietje.nl IN  A 1.2.3.4
  // pietje.nl should now NOT match, but www.pietje.nl should

  string subdomain=target;
  string::size_type pos;

  while((pos=subdomain.find("."))!=string::npos) {
    subdomain=subdomain.substr(pos+1);
    // DLOG();

    string searchstr=string("*.")+subdomain;

    B.lookup(QType(QType::ANY), searchstr,p); // start our search at the backend

    while(B.get(rr)) { // read results
      if(retargeted)
        continue;
      found=true;
      if((p->qtype.getCode()==QType::ANY || rr.qtype==p->qtype) || rr.qtype.getCode()==QType::CNAME) {
        rr.qname=target;

        if(d_doFancyRecords && p->qtype.getCode()==QType::ANY && (rr.qtype.getCode()==QType::URL || rr.qtype.getCode()==QType::CURL)) {
          rr.content=::arg()["urlredirector"];
          rr.qtype=QType::A; 
        }

        r->addRecord(rr);  // and add
        if(rr.qtype.getCode()==QType::CNAME) {
          if(target==rr.content) {
            L<<Logger::Error<<"Ignoring wildcard CNAME '"<<rr.qname<<"' pointing at itself"<<endl;
            r->setRcode(RCode::ServFail);
            continue;
          }
          
          DLOG(L<<Logger::Error<<"Retargeting because of wildcard cname, from "<<target<<" to "<<rr.content<<endl);
          
          target=rr.content; // retarget 
          retargeted=true;
        }
      }
      else if(d_doFancyRecords && ::arg().mustDo("wildcard-url") && p->qtype.getCode()==QType::A && rr.qtype.getName()=="URL") {
        rr.content=::arg()["urlredirector"];
        rr.qtype=QType::A; 
        rr.qname=target;
        
        r->addRecord(rr);
      }
    }
    if(found) {
      DLOG(L<<"Wildcard match on '"<<string("*.")+subdomain<<"'"<<", retargeted="<<retargeted<<endl);
      return retargeted ? 2 : 1;
    }
  }
  DLOG(L<<"Returning no hit for '"<<string("*.")+subdomain<<"'"<<endl);
  return 0;
}

/** dangling is declared true if we were unable to resolve everything */
int PacketHandler::doAdditionalProcessingAndDropAA(DNSPacket *p, DNSPacket *r, const SOAData& soadata)
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

    for(vector<DNSResourceRecord *>::const_iterator i=arrs.begin();
        i!=arrs.end();	++i) 
      crrs.push_back(**i);

    // we now have a copy, push_back on packet might reallocate!
    for(vector<DNSResourceRecord>::const_iterator i=crrs.begin();
        i!=crrs.end();
        ++i) {
      
      if(r->d.aa && !i->qname.empty() && i->qtype.getCode()==QType::NS && !B.getSOA(i->qname,sd,p)) { // drop AA in case of non-SOA-level NS answer, except for root referral
        r->setA(false);
        //	i->d_place=DNSResourceRecord::AUTHORITY; // XXX FIXME
      }

      QType qtypes[2];
      qtypes[0]="A"; qtypes[1]="AAAA";
      for(int n=0 ; n < d_doIPv6AdditionalProcessing + 1; ++n) {
        if (i->qtype.getCode()==QType::SRV) {
          vector<string>parts;
          stringtok(parts,i->content);
          if (parts.size() >= 3) {
            B.lookup(qtypes[n],parts[2],p);
          }
          else
            continue;
        }
        else {
          B.lookup(qtypes[n],i->content,p);
        }
        bool foundOne=false;
        while(B.get(rr)) {
          foundOne=true;
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
  // <<"We should emit '"<<begin<<"' - ('"<<toNSEC<<"') - '"<<end<<"'"<<endl;
  NSECRecordContent nrc;
  nrc.d_set.insert(QType::RRSIG);
  nrc.d_set.insert(QType::NSEC);
  if(sd.qname == begin)
    nrc.d_set.insert(QType::DNSKEY);

  DNSResourceRecord rr;
  rr.ttl = sd.default_ttl;
  B.lookup(QType(QType::ANY), begin);
  while(B.get(rr)) {
    if(rr.domain_id == sd.domain_id) 
      nrc.d_set.insert(rr.qtype.getCode());    
  }
  
  nrc.d_next=end;

  rr.qname=begin;
  // we can leave ttl untouched, either it is the default, or it is what we retrieved above
  rr.qtype=QType::NSEC;
  rr.content=nrc.getZoneRepresentation();
  rr.d_place = (mode == 2 ) ? DNSResourceRecord::ANSWER: DNSResourceRecord::AUTHORITY;
  rr.auth = true;
  
  r->addRecord(rr);
}

void emitNSEC3(DNSBackend& B, const NSEC3PARAMRecordContent& ns3prc, const SOAData& sd, const std::string& unhashed, const std::string& begin, const std::string& end, const std::string& toNSEC3, DNSPacket *r, int mode)
{
//  cerr<<"We should emit NSEC3 '"<<toLower(toBase32Hex(begin))<<"' - ('"<<toNSEC3<<"') - '"<<toLower(toBase32Hex(end))<<"' (unhashed: '"<<unhashed<<"')"<<endl;
  NSEC3RecordContent n3rc;
  n3rc.d_set.insert(QType::RRSIG);
  n3rc.d_salt=ns3prc.d_salt;
  n3rc.d_flags = ns3prc.d_flags;
  n3rc.d_iterations = ns3prc.d_iterations;
  n3rc.d_algorithm = 1; // SHA1, fixed in PowerDNS for now

  DNSResourceRecord rr;
  rr.ttl = sd.default_ttl;
  B.lookup(QType(QType::ANY), unhashed);
  while(B.get(rr)) {
    n3rc.d_set.insert(rr.qtype.getCode());    
  }

  if(unhashed == sd.qname) {
    n3rc.d_set.insert(QType::NSEC3PARAM);
    n3rc.d_set.insert(QType::DNSKEY);
  }
  
  n3rc.d_nexthash=end;

  rr.qname=dotConcat(toLower(toBase32Hex(begin)), sd.qname);
  
  rr.qtype=QType::NSEC3;
  rr.content=n3rc.getZoneRepresentation();
  
  rr.d_place = (mode == 2 ) ? DNSResourceRecord::ANSWER: DNSResourceRecord::AUTHORITY;
  rr.auth = true;
  r->addRecord(rr);
}

void PacketHandler::emitNSEC3(const NSEC3PARAMRecordContent& ns3prc, const SOAData& sd, const std::string& unhashed, const std::string& begin, const std::string& end, const std::string& toNSEC3, DNSPacket *r, int mode)
{
  ::emitNSEC3(B, ns3prc, sd, unhashed, begin, end, toNSEC3, r, mode);
  
}

/* mode 0 = no error -> an NSEC that starts with 'target', in authority section
   mode 1 = NXDOMAIN -> an NSEC from auth to first + a covering NSEC
   mode 2 = ANY or direct NSEC request  -> an NSEC that starts with 'target'
   mode 3 = a covering NSEC in the authority section (like 1, except for first)
*/
void PacketHandler::addNSECX(DNSPacket *p, DNSPacket *r, const string& target, const string& auth, int mode)
{
  NSEC3PARAMRecordContent ns3rc;
  // cerr<<"Doing NSEC3PARAM lookup for '"<<auth<<"', "<<p->qdomain<<"|"<<p->qtype.getName()<<": ";
  bool narrow;
  if(d_dk.getNSEC3PARAM(auth, &ns3rc, &narrow))  {
    // cerr<<"Present, narrow="<<narrow<<endl;
    addNSEC3(p, r, target, auth, ns3rc, narrow, mode);
  }
  else {
    // cerr<<"Not present"<<endl;
    addNSEC(p, r, target, auth, mode);
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


bool getNSEC3Hashes(bool narrow, DNSBackend* db, int id, const std::string& hashed, bool decrement, string& unhashed, string& before, string& after)
{
  bool ret;
  if(narrow) { // nsec3-narrow
    ret=true;
    before=hashed;
    if(decrement)
      decrementHash(before);
    after=hashed;
    incrementHash(after);
  }
  else {
    ret=db->getBeforeAndAfterNamesAbsolute(id, toLower(toBase32Hex(hashed)), unhashed, before, after);
    before=fromBase32Hex(before);
    after=fromBase32Hex(after);
  }
  // cerr<<"rgetNSEC3Hashes: "<<hashed<<", "<<unhashed<<", "<<before<<", "<<after<<endl;
  return ret;
}

void PacketHandler::addNSEC3(DNSPacket *p, DNSPacket *r, const string& target, const string& auth, const NSEC3PARAMRecordContent& ns3rc, bool narrow, int mode)
{
  string hashed;
  
  SOAData sd;
  sd.db = (DNSBackend*)-1;
  if(!B.getSOA(auth, sd)) {
    // cerr<<"Could not get SOA for domain in NSEC3\n";
    return;
  }
  // cerr<<"salt in ph: '"<<makeHexDump(ns3rc.d_salt)<<"', narrow="<<narrow<<endl;
  string unhashed, before,after;

  // now add the closest encloser
  unhashed=auth;
  hashed=hashQNameWithSalt(ns3rc.d_iterations, ns3rc.d_salt, unhashed);
  
  getNSEC3Hashes(narrow, sd.db, sd.domain_id,  hashed, false, unhashed, before, after); 
  DLOG(L<<"Done calling for closest encloser, before='"<<toBase32Hex(before)<<"', after='"<<toBase32Hex(after)<<"', unhashed: '"<<unhashed<<"'"<<endl);
  emitNSEC3(ns3rc, sd, unhashed, before, after, target, r, mode);

  // now add the main nsec3
  unhashed = p->qdomain;
  hashed=hashQNameWithSalt(ns3rc.d_iterations, ns3rc.d_salt, unhashed);
  getNSEC3Hashes(narrow, sd.db,sd.domain_id,  hashed, true, unhashed, before, after); 
  DLOG(L<<"Done calling for main, before='"<<toBase32Hex(before)<<"', after='"<<toBase32Hex(after)<<"', unhashed: '"<<unhashed<<"'"<<endl);
  emitNSEC3( ns3rc, sd, unhashed, before, after, target, r, mode);
  
  // now add the *
  unhashed=dotConcat("*", auth);
  hashed=hashQNameWithSalt(ns3rc.d_iterations, ns3rc.d_salt, unhashed);
  
  getNSEC3Hashes(narrow, sd.db, sd.domain_id,  hashed, true, unhashed, before, after); 
  DLOG(L<<"Done calling for '*', before='"<<toBase32Hex(before)<<"', after='"<<toBase32Hex(after)<<"', unhashed: '"<<unhashed<<"'"<<endl);
  emitNSEC3( ns3rc, sd, unhashed, before, after, target, r, mode);
}

void PacketHandler::addNSEC(DNSPacket *p, DNSPacket *r, const string& target, const string& auth, int mode)
{
  if(!p->d_dnssecOk)
    return;
  
  DLOG(L<<"Should add NSEC covering '"<<target<<"' from zone '"<<auth<<"', mode = "<<mode<<endl);
  SOAData sd;
  sd.db=(DNSBackend *)-1; // force uncached answer

  if(auth.empty()) {
    getAuth(p, &sd, target, 0);
  }
  else if(!B.getSOA(auth, sd)) {
    DLOG(L<<"Could not get SOA for domain"<<endl);
    return;
  }

  string before,after;
  //cerr<<"Calling getBeforeandAfter!"<<endl;
  sd.db->getBeforeAndAfterNames(sd.domain_id, auth, target, before, after);
  // cerr<<"Done calling, before='"<<before<<"', after='"<<after<<"'"<<endl;

  // this stuff is wrong (but it appears to work)
  
  if(mode ==0 || mode==2)
    emitNSEC(target, after, target, sd, r, mode);
  
  if(mode == 1)  {
    emitNSEC(before, after, target, sd, r, mode);

    // this one does wildcard denial, if applicable
    sd.db->getBeforeAndAfterNames(sd.domain_id, auth, auth, before, after);
    emitNSEC(before, after, auth, sd, r, mode);
  }

  if(mode == 3)
    emitNSEC(before, after, target, sd, r, mode);

  return;
}

bool PacketHandler::doDNSSECProcessing(DNSPacket *p, DNSPacket *r)
{
  if(!p->d_dnssecOk)
    return false;

  vector<DNSResourceRecord *> arrs=r->getAnswerRecords();
  if(arrs.empty()) 
    return false;
  
  DLOG(L<<"Have arrs "<<arrs.size()<<" records to sign"<<endl);
  vector<DNSResourceRecord> crrs;
  
  for(vector<DNSResourceRecord *>::const_iterator i=arrs.begin();
      i!=arrs.end();	++i) 
    crrs.push_back(**i);
  
  // we now have a copy, push_back on packet might reallocate!
  
  for(vector<DNSResourceRecord>::const_iterator i=crrs.begin();
      i!=crrs.end();
      ++i) {
    if(i->d_place!=DNSResourceRecord::ANSWER) 
      continue;
    
    B.lookup(QType(QType::RRSIG),i->qname,p);  
    DNSResourceRecord rr;
    while(B.get(rr)) {
      rr.d_place=DNSResourceRecord::ANSWER;
      if(splitField(rr.content, ' ').first==i->qtype.getName())
        r->addRecord(rr);
    }
  }
  
  return false;
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

  string account;
  DNSBackend *db;
  if(!B.superMasterBackend(p->getRemote(), p->qdomain, nsset, &account, &db)) {
    L<<Logger::Error<<"Unable to find backend willing to host "<<p->qdomain<<" for potential supermaster "<<p->getRemote()<<endl;
    return RCode::Refused;
  }
  db->createSlaveDomain(p->getRemote(),p->qdomain,account);
  Communicator.addSuckRequest(p->qdomain, p->getRemote());  
  L<<Logger::Warning<<"Created new slave zone '"<<p->qdomain<<"' from supermaster "<<p->getRemote()<<", queued axfr"<<endl;
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
         c =='-' || c == '_' || c=='*' || c=='.' || c=='/' || c=='@' || c==' ' || c=='\\'))
      return false;
  }
  return true;
}  

DNSPacket *PacketHandler::question(DNSPacket *p)
{
  bool shouldRecurse=false;
  DNSPacket *ret=questionOrRecurse(p, &shouldRecurse);
  if(shouldRecurse) {
    DP->sendPacket(p);
  }
  return ret;
}

void PacketHandler::synthesiseRRSIGs(DNSPacket* p, DNSPacket* r)
{
  DLOG(L<<"Need to fake up the RRSIGs if someone asked for them explicitly"<<endl);
  typedef map<uint16_t, vector<shared_ptr<DNSRecordContent> > > records_t;
  records_t records;

  NSECRecordContent nrc;
  nrc.d_set.insert(QType::RRSIG);
  nrc.d_set.insert(QType::NSEC);

  DNSResourceRecord rr;

  SOAData sd;
  sd.db=(DNSBackend *)-1; // force uncached answer
  getAuth(p, &sd, p->qdomain, 0);

  rr.ttl=sd.default_ttl;
  B.lookup(QType(QType::ANY), p->qdomain, p);

  while(B.get(rr)) {
    if(!rr.auth) 
      continue;
    
    // this deals with the 'prio' mismatch!
    if(rr.qtype.getCode()==QType::MX || rr.qtype.getCode() == QType::SRV) {  
      rr.content = lexical_cast<string>(rr.priority) + " " + rr.content;
    }
    
    if(!rr.content.empty() && rr.qtype.getCode()==QType::TXT && rr.content[0]!='"') {
      rr.content="\""+rr.content+"\"";
    }
    if(rr.content.empty())  // empty contents confuse the MOADNS setup
      rr.content=".";
    shared_ptr<DNSRecordContent> drc(DNSRecordContent::mastermake(rr.qtype.getCode(), 1, rr.content)); 
    
    records[rr.qtype.getCode()].push_back(drc);
    nrc.d_set.insert(rr.qtype.getCode());
  }
  bool narrow;
  NSEC3PARAMRecordContent ns3pr;
  bool doNSEC3= d_dk.getNSEC3PARAM(sd.qname, &ns3pr, &narrow);
  if(doNSEC3) {
    DLOG(L<<"We don't yet add NSEC3 to explicit RRSIG queries correctly yet! (narrow="<<narrow<<")"<<endl);
  }
  else {
    // now get the NSEC too (since we must sign it!)
    string before,after;
    sd.db->getBeforeAndAfterNames(sd.domain_id, sd.qname, p->qdomain, before, after);
  
    nrc.d_next=after;
  
    rr.qname=p->qdomain;
    // rr.ttl is already set.. we hope
    rr.qtype=QType::NSEC;
    rr.content=nrc.getZoneRepresentation();
    records[QType::NSEC].push_back(shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(rr.qtype.getCode(), 1, rr.content)));
  
    // ok, the NSEC is in..
  }
  DLOG(L<<"Have "<<records.size()<<" rrsets to sign"<<endl);

  rr.qname = p->qdomain;
  // again, rr.ttl is already set
  rr.auth = 0; // please don't sign this!
  rr.d_place = DNSResourceRecord::ANSWER;
  rr.qtype = QType::RRSIG;

  BOOST_FOREACH(records_t::value_type& iter, records) {
    vector<RRSIGRecordContent> rrcs;
    
    getRRSIGsForRRSET(d_dk, sd.qname, p->qdomain, iter.first, 3600, iter.second, rrcs, iter.first == QType::DNSKEY);
    BOOST_FOREACH(RRSIGRecordContent& rrc, rrcs) {
      rr.content=rrc.getZoneRepresentation();
      r->addRecord(rr);
    }
  }
}

void PacketHandler::makeNXDomain(DNSPacket* p, DNSPacket* r, const std::string& target, SOAData& sd)
{
  DNSResourceRecord rr;
  rr.qname=sd.qname;
  rr.qtype=QType::SOA;
  rr.content=serializeSOAData(sd);
  rr.ttl=sd.ttl;
  rr.domain_id=sd.domain_id;
  rr.d_place=DNSResourceRecord::AUTHORITY;
  rr.auth = 1;
  rr.scopeMask = sd.scopeMask;
  r->addRecord(rr);
  
  if(p->d_dnssecOk && d_dk.isSecuredZone(sd.qname))
    addNSECX(p, r, target, sd.qname, 1);
  
  r->setRcode(RCode::NXDomain);  
  S.ringAccount("nxdomain-queries",p->qdomain+"/"+p->qtype.getName());
}

void PacketHandler::makeNOError(DNSPacket* p, DNSPacket* r, const std::string& target, SOAData& sd)
{
  DNSResourceRecord rr;
  rr.qname=sd.qname;
  rr.qtype=QType::SOA;
  rr.content=serializeSOAData(sd);
  rr.ttl=sd.ttl;
  rr.domain_id=sd.domain_id;
  rr.d_place=DNSResourceRecord::AUTHORITY;
  rr.auth = 1;
  r->addRecord(rr);

  if(p->d_dnssecOk && d_dk.isSecuredZone(sd.qname))
    addNSECX(p, r, target, sd.qname, 0);

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
    rr.auth=true; // please sign it!
    r->addRecord(rr);
  }
  return gotOne;
}

bool PacketHandler::tryReferral(DNSPacket *p, DNSPacket*r, SOAData& sd, const string &target)
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
  r->setA(false);

  if(p->d_dnssecOk && d_dk.isSecuredZone(sd.qname) && !addDSforNS(p, r, sd, rrset.begin()->qname))
    addNSECX(p, r, rrset.begin()->qname, sd.qname, 0);
  
  return true;
}

void PacketHandler::completeANYRecords(DNSPacket *p, DNSPacket*r, SOAData& sd, const string &target)
{
  if(!p->d_dnssecOk)
    ; // cerr<<"Need to add all the RRSIGs too for '"<<target<<"', should do this manually since DNSSEC was not requested"<<endl;
  //  cerr<<"Need to add all the NSEC too.."<<endl; /// XXX FIXME THE ABOVE IF IS WEIRD
  
  if(!d_dk.isSecuredZone(sd.qname))
    return;
    
  addNSECX(p, r, target, sd.qname, 2); 
  if(pdns_iequals(sd.qname, p->qdomain)) {
    DNSSECKeeper::keyset_t zskset = d_dk.getKeys(p->qdomain);
    DNSResourceRecord rr;
    BOOST_FOREACH(DNSSECKeeper::keyset_t::value_type value, zskset) {
      rr.qtype=QType::DNSKEY;
      rr.ttl=sd.default_ttl;
      rr.qname=p->qdomain;
      rr.content=value.first.getDNSKEY().getZoneRepresentation();
      rr.auth = true;
      r->addRecord(rr);
    }
  }
}

bool PacketHandler::tryWildcard(DNSPacket *p, DNSPacket*r, SOAData& sd, string &target, bool& retargeted, bool& nodata)
{
  retargeted = nodata = false;

  vector<DNSResourceRecord> rrset;
  if(!getBestWildcard(p, sd, target, &rrset))
    return false;

  if(rrset.empty()) {
    DLOG(L<<"Wildcard matched something, but not of the correct type"<<endl);
    nodata=true;
  }
  else {
    DLOG(L<<"The best wildcard match: "<<rrset.begin()->qname<<endl);
    BOOST_FOREACH(DNSResourceRecord rr, rrset) {
      rr.wildcardname = rr.qname;
      rr.qname=target;

      if(rr.qtype.getCode() == QType::CNAME)  {
        retargeted=true;
        target=rr.content;
      }
  
      DLOG(L<<"\tadding '"<<rr.content<<"'"<<endl);
      rr.d_place=DNSResourceRecord::ANSWER;
      r->addRecord(rr);
    }
  }
  if(p->d_dnssecOk && d_dk.isSecuredZone(sd.qname)) {
    addNSECX(p, r, p->qdomain, sd.qname, 3);
  }
  return true;
}

//! Called by the Distributor to ask a question. Returns 0 in case of an error
DNSPacket *PacketHandler::questionOrRecurse(DNSPacket *p, bool *shouldRecurse)
{
  *shouldRecurse=false;
  DNSResourceRecord rr;
  SOAData sd;
  sd.db=0;
  
  string subdomain="";
  string soa;
  int retargetcount=0;
  set<string, CIStringCompare> authSet;

  vector<DNSResourceRecord> rrset;
  bool weDone=0, weRedirected=0, weHaveUnauth=0;

  DNSPacket *r=0;
  bool noCache=false;
  
  if(p->d.qr) { // QR bit from dns packet (thanks RA from N)
    L<<Logger::Error<<"Received an answer (non-query) packet from "<<p->getRemote()<<", dropping"<<endl;
    S.inc("corrupt-packets");
    return 0;
  }

  if(p->d_havetsig) {
    string keyname, secret;
    TSIGRecordContent trc;
    if(!checkForCorrectTSIG(p, &B, &keyname, &secret, &trc)) {
      r=p->replyPacket();  // generate an empty reply packet
      if(d_logDNSDetails)
        L<<Logger::Error<<"Received a TSIG signed message with a non-validating key"<<endl;
      r->setRcode(RCode::NotAuth);
      return r;
    }
    p->setTSIGDetails(trc, keyname, secret, trc.d_mac); // this will get copied by replyPacket()
    noCache=true;
  }
  
  r=p->replyPacket();  // generate an empty reply packet, possibly with TSIG details inside
  
  try {    

    // XXX FIXME do this in DNSPacket::parse ?

    if(!validDNSName(p->qdomain)) {
      if(d_logDNSDetails)
        L<<Logger::Error<<"Received a malformed qdomain from "<<p->getRemote()<<", '"<<p->qdomain<<"': sending servfail"<<endl;
      S.inc("corrupt-packets");
      r->setRcode(RCode::ServFail);
      return r;
    }
    if(p->d.opcode) { // non-zero opcode (again thanks RA!)
      if(p->d.opcode==Opcode::Update) {
        if(::arg().mustDo("log-failed-updates"))
          L<<Logger::Notice<<"Received an UPDATE opcode from "<<p->getRemote()<<" for "<<p->qdomain<<", sending NOTIMP"<<endl;
        r->setRcode(RCode::NotImp); // notimp;
        return r; 
      }
      else if(p->d.opcode==Opcode::Notify) {
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

    // L<<Logger::Warning<<"Query for '"<<p->qdomain<<"' "<<p->qtype.getName()<<" from "<<p->getRemote()<<endl;
    
    r->d.ra = (p->d.rd && d_doRecursion && DP->recurseFor(p));  // make sure we set ra if rd was set, and we'll do it

    if(p->qtype.getCode()==QType::IXFR) {
      r->setRcode(RCode::NotImp);
      return r;
    }

    // please don't query fancy records directly!
    if(d_doFancyRecords && (p->qtype.getCode()==QType::URL || p->qtype.getCode()==QType::CURL || p->qtype.getCode()==QType::MBOXFW)) {
      r->setRcode(RCode::ServFail);
      return r;
    }
    
    string target=p->qdomain;
    
    if(doVersionRequest(p,r,target)) // catch version.bind requests
      goto sendit;

    if(p->qclass==255) // any class query 
      r->setA(false);
    else if(p->qclass != QClass::IN) // we only know about IN, so we don't find anything
      goto sendit;

  retargeted:;
    if(retargetcount > 10) {    // XXX FIXME, retargetcount++?
      r->setRcode(RCode::ServFail);
      return r;
    }
    
    if(!getAuth(p, &sd, target, 0)) {
      DLOG(L<<Logger::Error<<"We have no authority over zone '"<<target<<"'"<<endl);
      if(r->d.ra) {
        DLOG(L<<Logger::Error<<"Recursion is available for this remote, doing that"<<endl);
        *shouldRecurse=true;
        delete r;
        return 0;
      }
      
      if(!retargetcount)
        r->setA(false); // drop AA if we never had a SOA in the first place
      if(::arg().mustDo("send-root-referral")) {
        DLOG(L<<Logger::Warning<<"Adding root-referral"<<endl);
        addRootReferral(r);
      }
      else {
        DLOG(L<<Logger::Warning<<"setting 'No Error'"<<endl);
      }
      goto sendit;
    }
    DLOG(L<<Logger::Error<<"We have authority, zone='"<<sd.qname<<"', id="<<sd.domain_id<<endl);
    authSet.insert(sd.qname); 

    if(pdns_iequals(sd.qname, p->qdomain)) {
      if(doDNSKEYRequest(p,r, sd))  
        goto sendit;
  
      if(doNSEC3PARAMRequest(p,r, sd)) 
        goto sendit;
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
    if(p->qtype.getCode() == QType::NSEC && p->d_dnssecOk && d_dk.isSecuredZone(sd.qname) && !d_dk.getNSEC3PARAM(sd.qname, 0)) {
      addNSEC(p, r, target, sd.qname, 2); // only NSEC please
      goto sendit;
    }

    // this TRUMPS a cname!
    if(p->qtype.getCode() == QType::RRSIG && d_dk.isSecuredZone(sd.qname)) {
      synthesiseRRSIGs(p, r);
      goto sendit;  
    }

    DLOG(L<<"Checking for referrals first, unless this is a DS query"<<endl);
    if(p->qtype.getCode() != QType::DS && tryReferral(p, r, sd, target))
      goto sendit;

    DLOG(L<<"Got no referrals, trying ANY"<<endl);

    // see what we get..
    B.lookup(QType(QType::ANY), target, p, sd.domain_id);
    rrset.clear();
    weDone = weRedirected = weHaveUnauth = 0;
    
    while(B.get(rr)) {
      if(rr.qtype.getCode() == QType::DS)
        rr.auth = 1;
      // cerr<<"Auth: "<<rr.auth<<", "<<(rr.qtype == p->qtype)<<", "<<rr.qtype.getName()<<endl;
      if((p->qtype.getCode() == QType::ANY || rr.qtype == p->qtype) && rr.auth) 
        weDone=1;
      // the line below fakes 'unauth NS' for delegations for non-DNSSEC backends.
      if((rr.qtype == p->qtype && !rr.auth) || (rr.qtype.getCode() == QType::NS && (!rr.auth || !pdns_iequals(sd.qname, rr.qname))))
        weHaveUnauth=1;

      if(rr.qtype.getCode() == QType::CNAME && p->qtype.getCode() != QType::CNAME) 
        weRedirected=1;
        
      if(rr.qtype.getCode() == QType::SOA && pdns_iequals(rr.qname, sd.qname)) { // fix up possible SOA adjustments for this zone
        rr.content=serializeSOAData(sd);
        rr.ttl=sd.ttl;
        rr.domain_id=sd.domain_id;
        rr.auth = true;
      }
      
      rrset.push_back(rr);
    }

    DLOG(L<<"After first ANY query for '"<<target<<"', id="<<sd.domain_id<<": weDone="<<weDone<<", weHaveUnauth="<<weHaveUnauth<<", weRedirected="<<weRedirected<<endl);
    if(p->qtype.getCode() == QType::DS && weHaveUnauth &&  !weDone && !weRedirected && d_dk.isSecuredZone(sd.qname)) {
      DLOG(L<<"Q for DS of a name for which we do have NS, but for which we don't have on a zone with DNSSEC need to provide an AUTH answer that proves we don't"<<endl);
      makeNOError(p, r, target, sd);
      goto sendit;
    }

    if(rrset.empty()) {
      DLOG(L<<"checking qtype.getCode() ["<<(p->qtype.getCode())<<"] against QType::DS ["<<(QType::DS)<<endl);
      if(p->qtype.getCode() == QType::DS)
      {
        DLOG(L<<"DS query found no direct result, trying referral now"<<endl);
        if(tryReferral(p, r, sd, target))
        {
          DLOG(L<<"got referral for DS query"<<endl);
          goto sendit;
        }
      }

      DLOG(L<<Logger::Warning<<"Found nothing in the by-name ANY, but let's try wildcards.."<<endl);
      bool wereRetargeted(false), nodata(false);
      if(tryWildcard(p, r, sd, target, wereRetargeted, nodata)) {
        if(wereRetargeted) {
          retargetcount++;
          goto retargeted;
        }
        if(nodata)
          makeNOError(p, r, target, sd);
        goto sendit;
      }
      else
      {        
        makeNXDomain(p, r, target, sd);
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
      BOOST_FOREACH(rr, rrset) {
        if((p->qtype.getCode() == QType::ANY || rr.qtype == p->qtype) && rr.auth) 
          r->addRecord(rr);
      }

      if(p->qtype.getCode() == QType::ANY) {
        completeANYRecords(p, r, sd, target);
      }

      goto sendit;
    }
    else if(weHaveUnauth) {
      DLOG(L<<"Have unauth data, so need to hunt for best NS records"<<endl);
      if(tryReferral(p, r, sd, target))
        goto sendit;
      L<<Logger::Error<<"Should not get here ("<<p->qdomain<<"|"<<p->qtype.getCode()<<"): please run pdnssec rectify-zone "<<sd.qname<<endl;
    }
    else {
      DLOG(L<<"Have some data, but not the right data"<<endl);
      makeNOError(p, r, target, sd);
    }
    
  sendit:;
    if(doAdditionalProcessingAndDropAA(p, r, sd)<0) {
      delete r;
      return 0;
    }

    //    doDNSSECProcessing(p, r);
    editSOA(d_dk, sd.qname, r);
    
    if(p->d_dnssecOk)
      addRRSigs(d_dk, B, authSet, r->getRRS());
      
    r->wrapup(); // needed for inserting in cache
    if(!noCache)
      PC.insert(p, r, r->getMinTTL()); // in the packet cache
  }
  catch(DBException &e) {
    L<<Logger::Error<<"Database module reported condition which prevented lookup ("+e.reason+") sending out servfail"<<endl;
    r->setRcode(RCode::ServFail);
    S.inc("servfail-packets");
    S.ringAccount("servfail-queries",p->qdomain);
  }
  catch(AhuException &e) {
    L<<Logger::Error<<"Database module reported condition which prevented lookup ("+e.reason+") sending out servfail"<<endl;
    r->setRcode(RCode::ServFail);
    S.inc("servfail-packets");
    S.ringAccount("servfail-queries",p->qdomain);
  }
  catch(std::exception &e) {
    L<<Logger::Error<<"Exception building answer packet ("<<e.what()<<") sending out servfail"<<endl;
    delete r;
    r=p->replyPacket();  // generate an empty reply packet    
    r->setRcode(RCode::ServFail);
    S.inc("servfail-packets");
    S.ringAccount("servfail-queries",p->qdomain);
  }
  return r; 

}

