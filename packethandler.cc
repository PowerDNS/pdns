 /*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2007  PowerDNS.COM BV

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
#include "utility.hh"
#include <string>
#include <sys/types.h>
#include <boost/algorithm/string.hpp>
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

extern StatBag S;
extern PacketCache PC;  
extern CommunicatorClass Communicator;
extern DNSProxy *DP;

int PacketHandler::s_count;
extern string s_programname;

PacketHandler::PacketHandler():B(s_programname)
{
  s_count++;
  d_doFancyRecords = (arg()["fancy-records"]!="no");
  d_doWildcards = (arg()["wildcards"]!="no");
  d_doCNAME = (arg()["skip-cname"]=="no");
  d_doRecursion= arg().mustDo("recursor");
  d_logDNSDetails= arg().mustDo("log-dns-details");
  d_doIPv6AdditionalProcessing = arg().mustDo("do-ipv6-additional-processing");
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

  if(boost::iequals(arg()["send-root-referral"], "lean"))
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
    rr.content=arg()["smtpredirector"];
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
    rr.content=arg()["urlredirector"];
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
    rr.content=arg()["urlredirector"];
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

int PacketHandler::doDNSCheckRequest(DNSPacket *p, DNSPacket *r, string &target)
{
  int result = 0;
  DNSResourceRecord rr;

  if (p->qclass == 3 && p->qtype.getName() == "HINFO") {
    rr.content = "PowerDNS $Id$";
    rr.ttl = 5;
    rr.qname=target;
    rr.qtype=13; // hinfo
    r->addRecord(rr);
    result = 1;
  }
  
  return result;
}

/** This catches version requests. Returns 1 if it was handled, 0 if it wasn't */
int PacketHandler::doVersionRequest(DNSPacket *p, DNSPacket *r, string &target)
{
  DNSResourceRecord rr;
  
  // modes: anonymous, powerdns only, full, spoofed
  const string mode=arg()["version-string"];
  if(p->qtype.getCode()==QType::TXT && target=="version.bind") {// TXT
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
    rr.qtype=QType::TXT; // TXT
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
      found=true;
      if((p->qtype.getCode()==QType::ANY || rr.qtype==p->qtype) || rr.qtype.getCode()==QType::CNAME) {
	rr.qname=target;

	if(d_doFancyRecords && p->qtype.getCode()==QType::ANY && (rr.qtype.getCode()==QType::URL || rr.qtype.getCode()==QType::CURL)) {
	  rr.content=arg()["urlredirector"];
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
      else if(d_doFancyRecords && arg().mustDo("wildcard-url") && p->qtype.getCode()==QType::A && rr.qtype.getName()=="URL") {
	rr.content=arg()["urlredirector"];
	rr.qtype=QType::A; 
	rr.qname=target;
	
	r->addRecord(rr);
      }
    }
    if(found) {
      DLOG(L<<"Wildcard match on '"<<string("*.")+subdomain<<"'"<<endl);
      return retargeted ? 2 : 1;
    }
  }
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
      
      if(!i->qname.empty() && i->qtype.getCode()==QType::NS && !B.getSOA(i->qname,sd,p)) { // drop AA in case of non-SOA-level NS answer, except for root referral
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
	  if(rr.domain_id!=i->domain_id && arg()["out-of-zone-additional-processing"]=="no") {
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

    while(B.get(rr)) {
      if(rr.qtype.getCode()!=QType::NS || p->qtype.getCode()==QType::NS)
	hits++;
      if(!rfound && rr.qtype.getCode()==QType::CNAME) {
	found=true;
	r->addRecord(rr);
	target=rr.content; // for retargeting
      }
      if(shortcut && !found && rr.qtype==p->qtype) {
	rfound=true;
	r->addRecord(rr);
      }
    }
    if(hits && !found && !rfound && shortcut ) { // we found matching qnames but not a qtype
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
  if(!arg().mustDo("slave")) {
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
  if(p->getRemote() == arg()["trusted-notification-proxy"]) {
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
  bool noSameLevelNS;

  DNSPacket *r=0;
  try {    
    DLOG(L << Logger::Notice<<"Remote "<< p->remote.toString() <<" wants a type " << p->qtype.getName() << " ("<<p->qtype.getCode()<<") about '"<<p->qdomain << "'" << endl);

// XXX FIXME Find out why this isn't working!
#ifndef WIN32
    if(p->d.qr) { // QR bit from dns packet (thanks RA from N)
      L<<Logger::Error<<"Received an answer (non-query) packet from "<<p->getRemote()<<", dropping"<<endl;
      S.inc("corrupt-packets");
      return 0;
    }
#endif // WIN32

    // XXX FIXME do this in DNSPacket::parse ?

    if(!validDNSName(p->qdomain)) {
      if(arg().mustDo("log-dns-details"))
        L<<Logger::Error<<"Received a malformed qdomain from "<<p->getRemote()<<", '"<<p->qdomain<<"': dropping"<<endl;
      S.inc("corrupt-packets");
      return 0;
    }
    if(p->d.opcode) { // non-zero opcode (again thanks RA!)
      if(p->d.opcode==Opcode::Update) {
	if(arg().mustDo("log-failed-updates"))
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

    bool found=false;
    
    string target=p->qdomain;
    bool noCache=false;

    if (doDNSCheckRequest(p, r, target))
      goto sendit;
    
    if(doVersionRequest(p,r,target)) // catch version.bind requests
      goto sendit;

    if(p->qclass==255) // any class query 
      r->setA(false);
    else if(p->qclass!=1) // we only know about IN, so we don't find anything
      goto sendit;

    int mret;
  retargeted:;
    if(retargetcount++>10) {
      L<<Logger::Error<<"Detected wildcard CNAME loop involving '"<<target<<"'"<<endl;
      r->setRcode(RCode::ServFail);
      goto sendit;
    }
    mret=makeCanonic(p, r, target); // traverse CNAME chain until we have a useful record (may actually give the correct answer!)

    if(mret==2) { // there is some data, but not of the correct type
      r->clearRecords();
      DLOG(L<<"There is some data, but not of the correct type, adding SOA for NXRECORDSET"<<endl);
      SOAData sd;
      if(getAuth(p, &sd, target, 0)) {
	rr.qname=sd.qname;
	rr.qtype=QType::SOA;
	rr.content=serializeSOAData(sd);
	rr.ttl=sd.ttl;
	rr.domain_id=sd.domain_id;
	rr.d_place=DNSResourceRecord::AUTHORITY;
	r->addRecord(rr);
      }
    }

    if(mret == 1) 
      goto sendit; // this might be the end of it (client requested a CNAME, or we found the answer already)

    if(d_doFancyRecords) { // MBOXFW, URL <- fake records, emulated with MX and A
      int res=doFancyRecords(p,r,target);
      if(res) { // had a result
	if(res<0) // it was an error
	  r->setRcode(RCode::ServFail);
	goto sendit;  
      }
    }
    
    // now ready to start the real direct search

    if(p->qtype.getCode()==QType::SOA || p->qtype.getCode()==QType::ANY) { // this is special

      if(B.getSOA(target,sd,p)) {
	rr.qname=target;
	rr.qtype=QType::SOA;
	rr.content=serializeSOAData(sd);
	rr.ttl=sd.ttl;
	rr.domain_id=sd.domain_id;
	rr.d_place=DNSResourceRecord::ANSWER;
	r->addRecord(rr);
	if(p->qtype.getCode()==QType::SOA) { // we are done
	  goto sendit;
	}
      }
    }
    noSameLevelNS=true;

    if(p->qtype.getCode()!=QType::SOA) { // regular direct lookup
      B.lookup(QType(QType::ANY), target,p);
      
      while(B.get(rr)) {
	if(rr.qtype.getCode()==QType::SOA) // skip any direct SOA responses as they may be different
	  continue;
	if(rr.qtype==p->qtype || p->qtype.getCode()==QType::ANY ) {
	  DLOG(L<<"Found a direct answer: "<<rr.content<<endl);
	  found=true;
	  if(d_doFancyRecords && p->qtype.getCode()==QType::ANY && (rr.qtype.getCode()==QType::URL || rr.qtype.getCode()==QType::CURL)) {
	    rr.content=arg()["urlredirector"];
	    rr.qtype=QType::A; 
	    rr.qname=target;
	  }

	  r->addRecord(rr);  // and add
	}
	else
	  if(rr.qtype.getCode()==QType::NS)
	    noSameLevelNS=false;
      }
      
      if(p->qtype.getCode()==QType::ANY) {
	if(d_doFancyRecords) { 
	  int res=findMboxFW(p,r,target);
	  if(res<0)
	    L<<Logger::Error<<"Error finding a mailbox record after an ANY query"<<endl;
	  if(res>0) {
	    DLOG(L<<Logger::Error<<"Frobbed an MX in!"<<endl);
	    found=true;
	  }
	}
      }
      if(found) 
	goto sendit;
      
    }
    
    // not found yet, try wildcards (we only try here in case of recursion - we should check before we hand off)

    if(mret != 2 && p->d.rd && d_doRecursion && d_doWildcards) { 
      int res=doWildcardRecords(p,r,target);
      if(res) { // had a result
	// FIXME: wildCard may retarget us in the future
	if(res==1)  // had a straight result
	  goto sendit;  
	if(res==2)
	  goto retargeted;
	goto sendit;  
      }
    }

    // RECURSION CUT-OUT! 

    bool weAuth;
    int zoneId;
    zoneId=-1;
    
    if(p->d.rd && d_doRecursion && arg().mustDo("allow-recursion-override"))
      weAuth=getAuth(p, &sd, target, &zoneId);
    else
      weAuth=false;

    if(p->d.rd && d_doRecursion && !weAuth) {
      if(DP->recurseFor(p)) {
	*shouldRecurse=true;
	delete r;
	return 0;
      }
      else noCache=true;
    }
    
    string::size_type pos;
    
    DLOG(L<<"Nothing found so far for '"<<target<<"', do we even have authority over this domain?"<<endl);

    if(zoneId==-1)
      weAuth=getAuth(p, &sd, target, &zoneId); // TLDAuth perhaps

    if(weAuth) {
      DLOG(L<<Logger::Warning<<"Soa found: '"<<sd.qname<<"'"<<endl);
      ;
    }
    if(!weAuth) {
      DLOG(L<<Logger::Warning<<"We're not authoritative"<<endl);
      if(p->d.rd || target==p->qdomain) { // only servfail if we didn't follow a CNAME
	DLOG(L<<Logger::Warning<<"Adding SERVFAIL as we did not followed a CNAME"<<endl);
	if(d_logDNSDetails)
	  L<<Logger::Warning<<"Not authoritative for '"<< target<<"', sending servfail to "<<
	    p->getRemote()<< (p->d.rd ? " (recursion was desired)" : "") <<endl;

	r->setA(false);
	if(arg().mustDo("send-root-referral")) {
	  DLOG(L<<Logger::Warning<<"Adding root-referral"<<endl);
	  addRootReferral(r);
	}
	else {
	  DLOG(L<<Logger::Warning<<"Adding SERVFAIL"<<endl);
	  r->setRcode(RCode::ServFail);  // 'sorry' 
	}
      }
      else if(!p->d.rd) {
	addRootReferral(r);
	goto sendit;
      }
				       
      S.ringAccount("unauth-queries",p->qdomain+"/"+p->qtype.getName());
      S.ringAccount("remotes-unauth",p->getRemote());
    }
    else {
      DLOG(L<<Logger::Warning<<"We ARE authoritative for a subdomain of '"<<target<<"' ("<<sd.qname<<"), perhaps we have a suitable NS record then"<<endl);
      subdomain=target;
      found=0;
      pos=0; 
      
      do {
	if(pos) // skip dot
	  pos++;
	
	subdomain=subdomain.substr(pos);
	if(noSameLevelNS) { // skip first lookup if it is known not to exist
	  noSameLevelNS=false;
	  continue;
	}
	  
	if(!Utility::strcasecmp(subdomain.c_str(),sd.qname.c_str())) // about to break out of our zone
	  break; 

	B.lookup("NS", subdomain,p,zoneId);  // start our search at the backend
	
	while(B.get(rr)) {
	  if(target==p->qdomain && !found) { // don't strip data if we've been retargeted!
	    DLOG(L<<Logger::Warning<<"Clearing records - we've discovered we are auth (see cs 947)"<<endl);
	    r->clearRecords(); // we need to start out with an empty slate
	  }
	  found=true;
	  rr.d_place=DNSResourceRecord::AUTHORITY; // this for the authority section
	  r->addRecord(rr);
	}
	if(found || (!subdomain.empty() && subdomain[0]=='.')) {  // this catches '..'
	  r->setA(false);  // send out an NS referral, which should be unauth
	  break;
	}
      }while((pos=subdomain.find("."))!=string::npos);
      
      if(!found) {
	// try wildcards then 
	if(d_doWildcards) { 
	  int res=doWildcardRecords(p,r,target);

	  if(res==1)  // had a straight result
	    goto sendit; 
	  if(res==2)
	    goto retargeted;
	}

	// we have authority but no answer, so we add the SOA for negative caching
	rr.qname=sd.qname;
	rr.qtype=QType::SOA;
	rr.content=serializeSOAData(sd);
	rr.ttl=sd.ttl;
	rr.domain_id=sd.domain_id;
	rr.d_place=DNSResourceRecord::AUTHORITY;
	r->addRecord(rr);


	// need to send NXDOMAIN if there are 0 records for whatever type for target
	
	B.lookup("ANY",target,p);
	while(B.get(rr))
	  found=true;
	
	if(!found) {
	  SOAData sd2;
	  if(B.getSOA(target,sd2,p)) // is there a SOA perhaps? (which may not appear in an ANY query)
	    found=true;
	}

	if(!found) { 
	  if(d_logDNSDetails)
	    L<<Logger::Notice<<"Authoritative NXDOMAIN to "<< p->getRemote() <<" for '"<<target<<"' ("<<p->qtype.getName()<<")"<<endl;

	  r->setRcode(RCode::NXDomain); 
	  S.ringAccount("nxdomain-queries",p->qdomain+"/"+p->qtype.getName());
	}
	else {
	  if(d_logDNSDetails)
	    L<<Logger::Notice<<"Authoritative empty NO ERROR to "<< p->getRemote() <<" for '"<<target<<"' ("<<p->qtype.getName()<<"), other types do exist"<<endl;
	  S.ringAccount("noerror-queries",p->qdomain+"/"+p->qtype.getName());
	}
      }
    }
    
    // whatever we've built so far, do additional processing
    
  sendit:;
    if(doAdditionalProcessingAndDropAA(p,r)<0)
      return 0;

    r->wrapup(); // needed for inserting in cache
    if(!noCache)
      PC.insert(p,r); // in the packet cache
  }
  catch(DBException &e) {
    L<<Logger::Error<<"Database module reported condition which prevented lookup ("+e.reason+") sending out servfail"<<endl;
    r->setRcode(RCode::ServFail);
    S.inc("servfail-packets");
    S.ringAccount("servfail-queries",p->qdomain);
  }
  catch(exception &e) {
    L<<Logger::Error<<"Exception building answer packet ("<<e.what()<<") sending out servfail"<<endl;
    delete r;
    r=p->replyPacket();  // generate an empty reply packet    
    r->setRcode(RCode::ServFail);
    S.inc("servfail-packets");
    S.ringAccount("servfail-queries",p->qdomain);
  }
  return r; 

}

