/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2010  PowerDNS.COM BV

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
#include <polarssl/rsa.h>
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

int PacketHandler::s_count;
extern string s_programname;

PacketHandler::PacketHandler():B(s_programname)
{
  s_count++;
  d_doFancyRecords = (::arg()["fancy-records"]!="no");
  d_doWildcards = (::arg()["wildcards"]!="no");
  d_doCNAME = (::arg()["skip-cname"]=="no");
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

  B.lookup("MBOXFW",string("%@")+target,p, zoneId);
      
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
      
  B.lookup("URL",target,p); // search for a URL before we search for an A
        
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
  
  B.lookup("CURL",target,p); // search for a URL before we search for an A
      
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
      if(!rr.auth)
        ret.push_back(rr);
    }
    if(!ret.empty())
      return ret;
  } while( chopOff( subdomain ) );   // 'www.powerdns.org' -> 'powerdns.org' -> 'org' -> ''
  return ret;
}

vector<DNSResourceRecord> PacketHandler::getBestWildcard(DNSPacket *p, SOAData& sd, const string &target)
{
  vector<DNSResourceRecord> ret;
  DNSResourceRecord rr;
  string subdomain(target);
  while( chopOff( subdomain ))  {
    B.lookup(QType(QType::ANY), "*."+subdomain, p, sd.domain_id);
    while(B.get(rr)) {
      if(rr.qtype == p->qtype ||rr.qtype.getCode() == QType::CNAME )
        ret.push_back(rr);
    }
    
    if(!ret.empty())
      return ret;
    
    if(subdomain == sd.qname) // stop at SOA
      break;
  } 

  return ret;
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
int PacketHandler::doAdditionalProcessingAndDropAA(DNSPacket *p, DNSPacket *r)
{
  DNSResourceRecord rr;
  SOAData sd;

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
        r->d.aa=false;
        //	i->d_place=DNSResourceRecord::AUTHORITY; // XXX FIXME
      }

      QType qtypes[2];
      qtypes[0]="A"; qtypes[1]="AAAA";
      for(int n=0 ; n < d_doIPv6AdditionalProcessing + 1; ++n) {
        B.lookup(qtypes[n],i->content,p);  
        bool foundOne=false;
        while(B.get(rr)) {
          foundOne=true;
          if(rr.domain_id!=i->domain_id && ::arg()["out-of-zone-additional-processing"]=="no") {
            DLOG(L<<Logger::Warning<<"Not including out-of-zone additional processing of "<<i->qname<<" ("<<rr.qname<<")"<<endl);
            continue; // not adding out-of-zone additional data
          }
          
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
  cerr<<"We should emit '"<<begin<<"' - ('"<<toNSEC<<"') - '"<<end<<"'"<<endl;
  NSECRecordContent nrc;
  nrc.d_set.insert(QType::RRSIG);
  nrc.d_set.insert(QType::NSEC);
  if(sd.qname == begin)
    nrc.d_set.insert(QType::DNSKEY);

  DNSResourceRecord rr;
  rr.ttl = sd.default_ttl;
  B.lookup(QType(QType::ANY), begin);
  while(B.get(rr)) {
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

void PacketHandler::emitNSEC3(const NSEC3PARAMRecordContent& ns3prc, const SOAData& sd, const std::string& unhashed, const std::string& begin, const std::string& end, const std::string& toNSEC3, DNSPacket *r, int mode)
{
  cerr<<"We should emit NSEC3 '"<<toLower(toBase32Hex(begin))<<"' - ('"<<toNSEC3<<"') - '"<<toLower(toBase32Hex(end))<<"' (unhashed: '"<<unhashed<<"')"<<endl;
  NSEC3RecordContent n3rc;
  n3rc.d_set.insert(QType::RRSIG);
  n3rc.d_salt=ns3prc.d_salt;
  n3rc.d_flags = 0;
  n3rc.d_iterations = ns3prc.d_iterations;
  n3rc.d_algorithm = 1; // ?

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




/* mode 0 = no error -> an NSEC that starts with 'target', in authority section
   mode 1 = NXDOMAIN -> an NSEC from auth to first + a covering NSEC
   mode 2 = ANY or direct NSEC request  -> an NSEC that starts with 'target'
   mode 3 = a covering NSEC in the authority section (like 1, except for first)
*/
void PacketHandler::addNSECX(DNSPacket *p, DNSPacket *r, const string& target, const string& auth, int mode)
{
  NSEC3PARAMRecordContent ns3rc;
  cerr<<"Doing NSEC3PARAM lookup for '"<<auth<<"', "<<p->qdomain<<"|"<<p->qtype.getName()<<": ";
  bool narrow;
  if(d_dk.getNSEC3PARAM(auth, &ns3rc, &narrow))  {
    cerr<<"Present, narrow="<<narrow<<endl;
    addNSEC3(p, r, target, auth, ns3rc, narrow, mode);
  }
  else {
    cerr<<"Not present"<<endl;
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


bool PacketHandler::getNSEC3Hashes(bool narrow, DNSBackend* db, int id, const std::string& hashed, bool decrement, string& unhashed, string& before, string& after)
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
    cerr<<"Could not get SOA for domain in NSEC3\n";
    return;
  }
  // cerr<<"salt in ph: '"<<makeHexDump(ns3rc.d_salt)<<"', narrow="<<narrow<<endl;
  string unhashed, before,after;

  // now add the closest encloser
  unhashed=auth;
  hashed=hashQNameWithSalt(ns3rc.d_iterations, ns3rc.d_salt, unhashed);
  
  getNSEC3Hashes(narrow, sd.db, sd.domain_id,  hashed, false, unhashed, before, after); 
  cerr<<"Done calling for closest encloser, before='"<<toBase32Hex(before)<<"', after='"<<toBase32Hex(after)<<"'"<<endl;
  emitNSEC3(ns3rc, sd, unhashed, before, after, target, r, mode);

  // now add the main nsec3
  unhashed = p->qdomain;
  hashed=hashQNameWithSalt(ns3rc.d_iterations, ns3rc.d_salt, unhashed);
  getNSEC3Hashes(narrow, sd.db,sd.domain_id,  hashed, true, unhashed, before, after); 
  cerr<<"Done calling for main, before='"<<toBase32Hex(before)<<"', after='"<<toBase32Hex(after)<<"'"<<endl;
  emitNSEC3( ns3rc, sd, unhashed, before, after, target, r, mode);
  
  // now add the *
  unhashed=dotConcat("*", auth);
  hashed=hashQNameWithSalt(ns3rc.d_iterations, ns3rc.d_salt, unhashed);
  
  getNSEC3Hashes(narrow, sd.db, sd.domain_id,  hashed, true, unhashed, before, after); 
  cerr<<"Done calling for '*', before='"<<toBase32Hex(before)<<"', after='"<<toBase32Hex(after)<<"'"<<endl;
  emitNSEC3( ns3rc, sd, unhashed, before, after, target, r, mode);
}

void PacketHandler::addNSEC(DNSPacket *p, DNSPacket *r, const string& target, const string& auth, int mode)
{
  if(!p->d_dnssecOk)
    return;
  
  cerr<<"Should add NSEC covering '"<<target<<"' from zone '"<<auth<<"', mode = "<<mode<<endl;
  SOAData sd;
  sd.db=(DNSBackend *)-1; // force uncached answer

  if(auth.empty()) {
    getAuth(p, &sd, target, 0);
  }
  else if(!B.getSOA(auth, sd)) {
    cerr<<"Could not get SOA for domain\n";
    return;
  }

  string before,after;
  cerr<<"Calling getBeforeandAfter!"<<endl;
  sd.db->getBeforeAndAfterNames(sd.domain_id, auth, target, before, after); 
  cerr<<"Done calling, before='"<<before<<"', after='"<<after<<"'"<<endl;

  // this stuff is wrong (but it appears to work)
  
  if(mode ==0 || mode==2)
    emitNSEC(target, after, target, sd, r, mode);
  
  if(mode == 1)  {
    emitNSEC(before, after, target, sd, r, mode);

    sd.db->getBeforeAndAfterNames(sd.domain_id, auth, auth, before, after); 
    emitNSEC(auth, after, auth, sd, r, mode);
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
  
  cerr<<"Have arrs "<<arrs.size()<<" records to sign\n";
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

/* returns 1 if everything is done & ready, 0 if the search should continue, 2 if a 'NO-ERROR' response should be generated */
int PacketHandler::makeCanonic(DNSPacket *p, DNSPacket *r, string &target)
{
  DNSResourceRecord rr;

  bool found=false, rfound=false;

  if(p->qtype.getCode()!=QType::CNAME && !d_doCNAME)
    return 0;

  // Traverse a CNAME chain if needed
  for(int numloops=0;;numloops++) {
    if(numloops==10) {
      L<<Logger::Error<<"Detected a CNAME loop involving "<<target<<", sending SERVFAIL"<<endl;
      r->setRcode(2);
      return 1;
    }

    B.lookup(QType(QType::ANY),target,p);
        
    bool shortcut=p->qtype.getCode()!=QType::SOA && p->qtype.getCode()!=QType::ANY;
    int hits=0;
    bool relevantNS=false;
    bool sawDS=false;
    bool crossedZoneCut = false;
    while(B.get(rr)) {
      if(rr.qtype.getCode() == QType::NS && p->qtype.getCode() != QType::NS) { // possible retargeting
        relevantNS=true;
      }

      if(rr.qtype.getCode()==QType::DS && p->qtype.getCode() == QType::NS && p->d_dnssecOk) {
        sawDS = true;
        r->addRecord(rr);
      }

      if(rr.qtype.getCode()!=QType::NS || p->qtype.getCode()==QType::NS)
        hits++;
      if(!rfound && rr.qtype.getCode()==QType::CNAME) {
        found=true;
        r->addRecord(rr);
        target=rr.content; // for retargeting
      }
      if(shortcut && !found && rr.qtype==p->qtype) {
        if(!rr.auth) {
        // no idea why this if is here
        }
	  
        rfound=true;
        r->addRecord(rr);
      }
    }

    if(crossedZoneCut) {
      cerr<<"Should return NS records, and this A/AAAA record in the additional section.."<<endl;
    }

    if(!sawDS && p->qtype.getCode() == QType::NS && p->d_dnssecOk && rfound) {
      addNSECX(p, r, p->qdomain, "", 2); // make it 'official' that we have no DS
    }

    if(hits && !relevantNS && !found && !rfound && shortcut ) { // XXX FIXME !numloops. we found matching qnames but not a qtype
      DLOG(L<<"Found matching qname, but not the qtype"<<endl);
      return 2;
    }

    if(rfound)
      return 1; // ANY lookup found the right answer immediately

    if(found) {
      if(p->qtype.getCode()==QType::CNAME) // they really wanted a CNAME!
        return 1;
      DLOG(L<<"Looping because of a CNAME to "<<target<<endl);
      found=false;
    }
    else 
      break;
  }

  // we now have what we really search for ready in 'target'
  return 0;
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
  Resolver::res_t nsset;
  try {
    Resolver resolver;
    uint32_t theirserial;
    resolver.getSoaSerial(p->getRemote(),p->qdomain, &theirserial);  
  
    resolver.resolve(p->getRemote(),p->qdomain.c_str(), QType::NS);

    nsset=resolver.result();
  }
  catch(ResolverException &re) {
    L<<Logger::Error<<"Error resolving SOA or NS at: "<< p->getRemote() <<": "<<re.reason<<endl;
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
    
  string authServer(p->getRemote());
  if(::arg().contains("trusted-notification-proxy", p->getRemote())) {
    L<<Logger::Error<<"Received NOTIFY for "<<p->qdomain<<" from trusted-notification-proxy "<< p->getRemote()<<endl;
    if(di.masters.empty()) {
      L<<Logger::Error<<"However, "<<p->qdomain<<" does not have any masters defined"<<endl;
      return RCode::Refused;
    }

    authServer = *di.masters.begin();

  }
  else if(!db->isMaster(p->qdomain, p->getRemote())) {
    L<<Logger::Error<<"Received NOTIFY for "<<p->qdomain<<" from "<<p->getRemote()<<" which is not a master"<<endl;
    return RCode::Refused;
  }

  uint32_t theirserial=0;

  /* to quote Rusty Russell - this code is so bad that you can actually hear it suck */
  /* this is an instant DoS, just spoof notifications from the address of the master and we block  */

  Resolver resolver;
  try {
    resolver.getSoaSerial(authServer, p->qdomain, &theirserial);
  }
  catch(ResolverException& re) {
    L<<Logger::Error<<re.reason<<endl;
    return RCode::ServFail;
  }

  if(theirserial<=di.serial) {
    L<<Logger::Error<<"Received NOTIFY for "<<p->qdomain<<" from "<< authServer <<", we are up to date: "<<
      theirserial<<"<="<<di.serial<<endl;
    return RCode::NoError;
  }
  else {
    L<<Logger::Error<<"Received valid NOTIFY for "<<p->qdomain<<" (id="<<di.id<<") from master "<<p->getRemote()<<": "<<
      theirserial<<" > "<<di.serial<<endl;

    Communicator.addSuckRequest(p->qdomain, authServer, true); // priority
  }
  return -1; 
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
         c =='-' || c == '_' || c=='*' || c=='.' || c=='/' || c=='@'))
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
  cerr<<"Need to fake up the RRSIGs if someone asked for them explicitly"<<endl;
  B.lookup(QType(QType::ANY), p->qdomain, p);
  
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

  cerr<<"Have "<<records.size()<<" rrsets to sign"<<endl;

  rr.qname = p->qdomain;
  // again, rr.ttl is already set
  rr.auth = 0; // please don't sign this!
  rr.d_place = DNSResourceRecord::ANSWER;
  rr.qtype = QType::RRSIG;

  BOOST_FOREACH(records_t::value_type& iter, records) {
    vector<RRSIGRecordContent> rrcs;
    
    getRRSIGsForRRSET(d_dk, p->qdomain, iter.first, 3600, iter.second, rrcs, iter.first == QType::DNSKEY);
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
  r->addRecord(rr);
  
  if(p->d_dnssecOk && d_dk.haveActiveKSKFor(sd.qname))
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

  if(p->d_dnssecOk && d_dk.haveActiveKSKFor(sd.qname))
    addNSECX(p, r, target, sd.qname, 0);

  S.ringAccount("noerror-queries",p->qdomain+"/"+p->qtype.getName());
}


bool PacketHandler::addDSforNS(DNSPacket* p, DNSPacket* r, SOAData& sd, const string& dsname)
{
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

bool PacketHandler::tryReferral(DNSPacket *p, DNSPacket*r, SOAData& sd, const string &target)
{
  vector<DNSResourceRecord> rrset = getBestReferralNS(p, sd, target);
  if(rrset.empty())
    return false;
  
  cerr<<"The best NS is: "<<rrset.begin()->qname<<endl;
  BOOST_FOREACH(DNSResourceRecord rr, rrset) {
    cerr<<"\tadding '"<<rr.content<<"'\n";
    rr.d_place=DNSResourceRecord::AUTHORITY;
    r->addRecord(rr);
  }
  r->setA(false);

  if(p->d_dnssecOk && d_dk.haveActiveKSKFor(sd.qname) && !addDSforNS(p, r, sd, rrset.begin()->qname))
    addNSECX(p, r, rrset.begin()->qname, sd.qname, 0);
  
  return true;
}

void PacketHandler::completeANYRecords(DNSPacket *p, DNSPacket*r, SOAData& sd, const string &target)
{
  if(!p->d_dnssecOk)
    cerr<<"Need to add all the RRSIGs too for '"<<target<<"', should do this manually since DNSSEC was not requested"<<endl;
  //  cerr<<"Need to add all the NSEC too.."<<endl; /// XXX FIXME THE ABOVE IF IS WEIRD
  
  if(!d_dk.haveActiveKSKFor(sd.qname))
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

bool PacketHandler::tryWildcard(DNSPacket *p, DNSPacket*r, SOAData& sd, string &target, bool& retargeted)
{
  retargeted=false;

  vector<DNSResourceRecord> rrset = getBestWildcard(p, sd, target);
  if(rrset.empty())
    return false;

  cerr<<"The best wildcard match: "<<rrset.begin()->qname<<endl;
  BOOST_FOREACH(DNSResourceRecord rr, rrset) {
    if(rr.qtype.getCode() == QType::CNAME)  {
      retargeted=true;
      target=rr.content;
    }

    rr.wildcardname = rr.qname;
    rr.qname=p->qdomain;
    cerr<<"\tadding '"<<rr.content<<"'\n";
    rr.d_place=DNSResourceRecord::ANSWER;
    r->addRecord(rr);
  }

  if(p->d_dnssecOk) {
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

  vector<DNSResourceRecord> rrset;
  bool weDone=0, weRedirected=0, weHaveUnauth=0;

  DNSPacket *r=0;
  try {    

    if(p->d.qr) { // QR bit from dns packet (thanks RA from N)
      L<<Logger::Error<<"Received an answer (non-query) packet from "<<p->getRemote()<<", dropping"<<endl;
      S.inc("corrupt-packets");
      return 0;
    }

    // XXX FIXME do this in DNSPacket::parse ?

    if(!validDNSName(p->qdomain)) {
      if(d_logDNSDetails)
        L<<Logger::Error<<"Received a malformed qdomain from "<<p->getRemote()<<", '"<<p->qdomain<<"': sending servfail"<<endl;
      S.inc("corrupt-packets");
      r=p->replyPacket(); 
      r->setRcode(RCode::ServFail);
      return r;
    }
    if(p->d.opcode) { // non-zero opcode (again thanks RA!)
      if(p->d.opcode==Opcode::Update) {
        if(::arg().mustDo("log-failed-updates"))
          L<<Logger::Notice<<"Received an UPDATE opcode from "<<p->getRemote()<<" for "<<p->qdomain<<", sending NOTIMP"<<endl;
        r=p->replyPacket(); 
        r->setRcode(RCode::NotImp); // notimp;
        return r; 
      }
      else if(p->d.opcode==Opcode::Notify) {
        int res=processNotify(p);
        if(res>=0) {
          DNSPacket *r=p->replyPacket();
          r->setRcode(res);
          r->setOpcode(Opcode::Notify);
          return r;
        }
        return 0;
      }
      
      L<<Logger::Error<<"Received an unknown opcode "<<p->d.opcode<<" from "<<p->getRemote()<<" for "<<p->qdomain<<endl;

      r=p->replyPacket(); 
      r->setRcode(RCode::NotImp); 
      return r; 
    }

    // L<<Logger::Warning<<"Query for '"<<p->qdomain<<"' "<<p->qtype.getName()<<" from "<<p->getRemote()<<endl;
    
    r=p->replyPacket();  // generate an empty reply packet
    if(p->d.rd && d_doRecursion && DP->recurseFor(p))  // make sure we set ra if rd was set, and we'll do it
      r->d.ra=true;

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
    // bool noCache=false;

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
      r->setA(false);
      if(::arg().mustDo("send-root-referral")) {
        DLOG(L<<Logger::Warning<<"Adding root-referral"<<endl);
        addRootReferral(r);
      }
      else {
        DLOG(L<<Logger::Warning<<"Adding SERVFAIL"<<endl);
        r->setRcode(RCode::ServFail);  // 'sorry' 
      }
      goto sendit;
    }
    DLOG(L<<Logger::Error<<"We have authority, zone='"<<sd.qname<<"', id="<<sd.domain_id<<endl);
    // we know we have authority

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
    if(p->qtype.getCode() == QType::NSEC && p->d_dnssecOk && !d_dk.getNSEC3PARAM(sd.qname, 0)) {
      addNSEC(p, r, target, sd.qname, 2); // only NSEC please
      goto sendit;
    }
    
    // this TRUMPS a cname!
    if(p->qtype.getCode() == QType::RRSIG && p->d_dnssecOk) {
      synthesiseRRSIGs(p, r);
      goto sendit;  
    }

    // see what we get..
    B.lookup(QType(QType::ANY), target, p, sd.domain_id);
    rrset.clear();
    weDone=weRedirected=weHaveUnauth=0;
    
    while(B.get(rr)) {
      if((p->qtype.getCode() == QType::ANY || rr.qtype == p->qtype) && rr.auth) 
        weDone=1;
      if((rr.qtype == p->qtype || rr.qtype.getCode() == QType::NS) && !rr.auth) 
        weHaveUnauth=1;

      if(rr.qtype.getCode() == QType::CNAME && p->qtype.getCode() != QType::CNAME) 
        weRedirected=1;
      rrset.push_back(rr);
    }

    //cerr<<"After first ANY query: weDone="<<weDone<<", weHaveUnauth="<<weHaveUnauth<<", weRedirected="<<weRedirected<<endl;

    if(rrset.empty()) {
      // try wildcards, and if they don't work, go look for NS records
      cerr<<"Found nothing in the ANY, but let's try wildcards.."<<endl;
      bool wereRetargeted;
      if(tryWildcard(p, r, sd, target, wereRetargeted)) {
        if(wereRetargeted) {
          retargetcount++;
          goto retargeted;
        }
        goto sendit;
      }
      cerr<<"Found nothing in the ANY and wildcards, let's try NS referral"<<endl;
      if(!tryReferral(p, r, sd, target))
        makeNXDomain(p, r, target, sd);

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
      cerr<<"Have unauth data, so need to hunt for best NS records"<<endl;
      if(tryReferral(p, r, sd, target))
        goto sendit;
      cerr<<"Should not get here: please run pdnssec rectify-zone "<<sd.qname<<endl;
    }
    else {
      cerr<<"Have some data, but not the right data"<<endl;
      makeNOError(p, r, target, sd);
    }
    
  sendit:;
    if(doAdditionalProcessingAndDropAA(p,r)<0)
      return 0;

    //    doDNSSECProcessing(p, r);

    r->wrapup(&d_dk); // needed for inserting in cache
    if(!p->d_tcp) {
      PC.insert(p, r); // in the packet cache
    }
  }
  catch(DBException &e) {
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

