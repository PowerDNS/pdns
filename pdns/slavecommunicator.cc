/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2011  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation; 

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
#include "base32.hh"
#include <errno.h>
#include "communicator.hh"
#include <set>
#include <boost/utility.hpp>
#include "dnsbackend.hh"
#include "ueberbackend.hh"
#include "packethandler.hh"
#include "resolver.hh"
#include "logger.hh"
#include "dns.hh"
#include "arguments.hh"
#include "session.hh"
#include "packetcache.hh"
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>
#include "base64.hh"
#include "inflighter.cc"
#include "lua-pdns-recursor.hh"
#include "namespaces.hh"
#include "common_startup.hh"
#include <boost/scoped_ptr.hpp>
using boost::scoped_ptr;

template<typename T> bool rfc1982LessThan(T a, T b)
{
  return ((signed)(a - b)) < 0;
}

void CommunicatorClass::addSuckRequest(const string &domain, const string &master, bool priority)
{
  Lock l(&d_lock);
  
  SuckRequest sr;
  sr.domain = domain;
  sr.master = master;
  pair<UniQueue::iterator, bool>  res;
  if(priority) {
    res=d_suckdomains.push_front(sr);
  }
  else {
    res=d_suckdomains.push_back(sr);
  }
  
  if(res.second) {
    d_suck_sem.post();
  }
}

void CommunicatorClass::suck(const string &domain,const string &remote)
{
  L<<Logger::Error<<"Initiating transfer of '"<<domain<<"' from remote '"<<remote<<"'"<<endl;
  uint32_t domain_id;
  PacketHandler P; // fresh UeberBackend

  DomainInfo di;
  di.backend=0;
  bool first=true;    
  try {
    UeberBackend *B=dynamic_cast<UeberBackend *>(P.getBackend());  // copy of the same UeberBackend
    NSEC3PARAMRecordContent ns3pr, hadNs3pr;
    bool narrow, hadNarrow=false;
    DNSSECKeeper dk; // has its own ueberbackend
    bool dnssecZone = false;
    bool haveNSEC3=false;
    if(dk.isSecuredZone(domain)) {
      dnssecZone=true;
      haveNSEC3=dk.getNSEC3PARAM(domain, &ns3pr, &narrow);
      if (haveNSEC3) {
        hadNs3pr = ns3pr;
        hadNarrow = narrow;
      }
    }

    const bool hadNSEC3 = haveNSEC3;
    const bool hadPresigned = dk.isPresigned(domain);
    const bool hadDnssecZone = dnssecZone;

    if(dnssecZone) {
      if(!haveNSEC3) 
        L<<Logger::Info<<"Adding NSEC ordering information"<<endl;
      else if(!narrow)
        L<<Logger::Info<<"Adding NSEC3 hashed ordering information for '"<<domain<<"'"<<endl;
      else 
        L<<Logger::Info<<"Erasing NSEC3 ordering since we are narrow, only setting 'auth' fields"<<endl;
    }    

    if(!B->getDomainInfo(domain, di) || !di.backend) { // di.backend and B are mostly identical
      L<<Logger::Error<<"Can't determine backend for domain '"<<domain<<"'"<<endl;
      return;
    }
    domain_id=di.id;

    Resolver::res_t recs;
    set<string> nsset, qnames, dsnames;
    
    ComboAddress raddr(remote, 53);
    
    string tsigkeyname, tsigalgorithm, tsigsecret;
  
    if(dk.getTSIGForAccess(domain, remote, &tsigkeyname)) {
      string tsigsecret64;
      if(B->getTSIGKey(tsigkeyname, &tsigalgorithm, &tsigsecret64))
      {
        B64Decode(tsigsecret64, tsigsecret);
      }
      else
      {
        L<<Logger::Error<<"TSIG key '"<<tsigkeyname<<"' not found, ignoring 'AXFR-MASTER-TSIG' for domain '"<<domain<<"'"<<endl;
        tsigkeyname="";
      }
    }
    
    scoped_ptr<PowerDNSLua> pdl;
    vector<string> scripts;
    if(B->getDomainMetadata(domain, "LUA-AXFR-SCRIPT", scripts) && !scripts.empty()) {
      try {
        pdl.reset(new PowerDNSLua(scripts[0]));
        L<<Logger::Info<<"Loaded Lua script '"<<scripts[0]<<"' to edit the incoming AXFR of '"<<domain<<"'"<<endl;
      }
      catch(std::exception& e) {
        L<<Logger::Error<<"Failed to load Lua editing script '"<<scripts[0]<<"' for incoming AXFR of '"<<domain<<"': "<<e.what()<<endl;
        return;
      }
    }
    AXFRRetriever retriever(raddr, domain.c_str(), tsigkeyname, tsigalgorithm, tsigsecret);

    bool gotPresigned = false;
    bool gotNSEC3 = false;
    bool gotOptOutFlag = false;
    unsigned int soa_serial = 0;
    while(retriever.getChunk(recs)) {
      if(first) {
        L<<Logger::Error<<"AXFR started for '"<<domain<<"', transaction started"<<endl;
        di.backend->startTransaction(domain, domain_id);
        first=false;
      }
      
      for(Resolver::res_t::iterator i=recs.begin();i!=recs.end();++i) {
        if(i->qtype.getCode() == QType::OPT || i->qtype.getCode() == QType::TSIG) // ignore EDNS0 & TSIG
          continue;
          
        if(i->qtype.getCode() == QType::SOA) {
          if(soa_serial != 0)
            continue; //skip the last SOA
          SOAData sd;
          fillSOAData(i->content,sd);
          soa_serial = sd.serial;
        }
          
        // we generate NSEC, NSEC3, NSEC3PARAM (sorry Olafur) on the fly, this could only confuse things
        if (i->qtype.getCode() == QType::NSEC3PARAM) {
          ns3pr = NSEC3PARAMRecordContent(i->content);
          narrow = false;
          dnssecZone = haveNSEC3 = gotPresigned = gotNSEC3 = true;
          continue;
        } else if (i->qtype.getCode() == QType::NSEC3) {
          dnssecZone = gotPresigned = true;
          gotOptOutFlag = NSEC3RecordContent(i->content).d_flags & 1;
          continue;
        } else if (i->qtype.getCode() == QType::NSEC) {
          dnssecZone = gotPresigned = true;
          continue;
        }
          
        if(!endsOn(i->qname, domain)) { 
          L<<Logger::Error<<"Remote "<<remote<<" tried to sneak in out-of-zone data '"<<i->qname<<"'|"<<i->qtype.getName()<<" during AXFR of zone '"<<domain<<"', ignoring"<<endl;
          continue;
        }
        
        if(i->qtype.getCode() == QType::NS && !pdns_iequals(i->qname, domain)) 
          nsset.insert(i->qname);
        if(i->qtype.getCode() != QType::RRSIG) // this excludes us hashing RRSIGs for NSEC(3)
          qnames.insert(i->qname);
        if(i->qtype.getCode() == QType::DS)
          dsnames.insert(i->qname);
          
        i->domain_id=domain_id;
#if 0
        if(i->qtype.getCode()>=60000)
          throw DBException("Database can't store unknown record type "+lexical_cast<string>(i->qtype.getCode()-1024));
#endif
        vector<DNSResourceRecord> out;
        if(pdl && pdl->axfrfilter(raddr, domain, *i, out)) {
          BOOST_FOREACH(const DNSResourceRecord& rr, out) {
            di.backend->feedRecord(rr);
            if(rr.qtype.getCode() == QType::NS && !pdns_iequals(rr.qname, domain)) 
              nsset.insert(rr.qname);
            if(rr.qtype.getCode() != QType::RRSIG) // this excludes us hashing RRSIGs for NSEC(3)
              qnames.insert(rr.qname);
            if(i->qtype.getCode() == QType::DS)
              dsnames.insert(i->qname);
          }
        }
        else {
          di.backend->feedRecord(*i);
        }
      }
    }

    if (hadPresigned && !gotNSEC3)
    {
      // we only had NSEC3 because we were a presigned zone...
      haveNSEC3 = false;
    }

    string hashed;
    BOOST_FOREACH(const string& qname, qnames)
    {
      string shorter(qname);
      bool auth=true;
      do {
        if(nsset.count(shorter)) {  
          auth=false;
          break;
        }
      }while(chopOff(shorter));
      
      if(dsnames.count(qname))
        auth=true;

      if(dnssecZone && haveNSEC3)
      {
        if(!narrow) { 
          hashed=toLower(toBase32Hex(hashQNameWithSalt(ns3pr.d_iterations, ns3pr.d_salt, qname)));
        }
        di.backend->updateDNSSECOrderAndAuthAbsolute(domain_id, qname, hashed, auth); // this should always be done
        if(!auth || dsnames.count(qname))
        {
          di.backend->nullifyDNSSECOrderNameAndAuth(domain_id, qname, "NS");
          di.backend->nullifyDNSSECOrderNameAndAuth(domain_id, qname, "A");
          di.backend->nullifyDNSSECOrderNameAndAuth(domain_id, qname, "AAAA");
        }
      }
      else // NSEC
      {
        di.backend->updateDNSSECOrderAndAuth(domain_id, domain, qname, auth);
        if(!auth || dsnames.count(qname))
        {
          di.backend->nullifyDNSSECOrderNameAndAuth(domain_id, qname, "A");
          di.backend->nullifyDNSSECOrderNameAndAuth(domain_id, qname, "AAAA");
        }
      }
    }
    di.backend->commitTransaction();
    di.backend->setFresh(domain_id);

    // now we also need to update the presigned flag and NSEC3PARAM
    // for the zone
    if (gotPresigned) {
      if (!hadDnssecZone && !hadPresigned) {
        // zone is now presigned
        dk.setPresigned(domain);
      }

      if (hadPresigned || !hadDnssecZone)
      {
        // this is a presigned zone, update NSEC3PARAM
        if (gotNSEC3) {
          ns3pr.d_flags = gotOptOutFlag ? 1 : 0;
         // only update if there was a change
          if (!hadNSEC3 || (narrow != hadNarrow) ||
              (ns3pr.d_algorithm != hadNs3pr.d_algorithm) ||
              (ns3pr.d_flags != hadNs3pr.d_flags) ||
              (ns3pr.d_iterations != hadNs3pr.d_iterations) ||
              (ns3pr.d_salt != hadNs3pr.d_salt)) {
            dk.setNSEC3PARAM(domain, ns3pr, narrow);
          }
        } else if (hadNSEC3) {
          dk.unsetNSEC3PARAM(domain);
        }
      }
    } else if (hadPresigned) {
      // zone is no longer presigned
      dk.unsetPresigned(domain);
      dk.unsetNSEC3PARAM(domain);
    }


    L<<Logger::Error<<"AXFR done for '"<<domain<<"', zone committed with serial number "<<soa_serial<<endl;
    if(::arg().mustDo("slave-renotify"))
      notifyDomain(domain);
  }
  catch(DBException &re) {
    L<<Logger::Error<<"Unable to feed record during incoming AXFR of '"+domain+"': "<<re.reason<<endl;
    if(di.backend && !first) {
      L<<Logger::Error<<"Aborting possible open transaction for domain '"<<domain<<"' AXFR"<<endl;
      di.backend->abortTransaction();
    }
  }
  catch(MOADNSException &re) {
    L<<Logger::Error<<"Unable to parse record during incoming AXFR of '"+domain+"' (MOADNSException): "<<re.what()<<endl;
    if(di.backend && !first) {
      L<<Logger::Error<<"Aborting possible open transaction for domain '"<<domain<<"' AXFR"<<endl;
      di.backend->abortTransaction();
    }
  }
  catch(std::exception &re) {
    L<<Logger::Error<<"Unable to parse record during incoming AXFR of '"+domain+"' (std::exception): "<<re.what()<<endl;
    if(di.backend && !first) {
      L<<Logger::Error<<"Aborting possible open transaction for domain '"<<domain<<"' AXFR"<<endl;
      di.backend->abortTransaction();
    }
  }
  catch(ResolverException &re) {
    L<<Logger::Error<<"Unable to AXFR zone '"+domain+"' from remote '"<<remote<<"' (resolver): "<<re.reason<<endl;
    if(di.backend && !first) {
      L<<Logger::Error<<"Aborting possible open transaction for domain '"<<domain<<"' AXFR"<<endl;
      di.backend->abortTransaction();
    }
  }
}
namespace {
struct QueryInfo
{
  struct timeval query_ttd;
  uint16_t id;
};

struct DomainNotificationInfo
{
  DomainInfo di;
  bool dnssecOk;
  string tsigkeyname, tsigalgname, tsigsecret;
};
}


struct SlaveSenderReceiver
{
  typedef pair<string, uint16_t> Identifier;
  
  struct Answer {
    uint32_t theirSerial;
    uint32_t theirInception;
    uint32_t theirExpire;
  };
  
  map<uint32_t, Answer> d_freshness;
  
  SlaveSenderReceiver()
  {
  }
  
  void deliverTimeout(const Identifier& i)
  {
  }
  
  Identifier send(DomainNotificationInfo& dni)
  {
    random_shuffle(dni.di.masters.begin(), dni.di.masters.end());
    try {
      ComboAddress remote(*dni.di.masters.begin());
      return make_pair(dni.di.zone, 
        d_resolver.sendResolve(ComboAddress(*dni.di.masters.begin(), 53), 
          dni.di.zone.c_str(), 
          QType::SOA, 
          dni.dnssecOk, dni.tsigkeyname, dni.tsigalgname, dni.tsigsecret)
      );
    }
    catch(AhuException& e) {
      throw runtime_error("While attempting to query freshness of '"+dni.di.zone+"': "+e.reason);
    }
  }
  
  bool receive(Identifier& id, Answer& a)
  {
    if(d_resolver.tryGetSOASerial(&id.first, &a.theirSerial, &a.theirInception, &a.theirExpire, &id.second)) {
      return 1;
    }
    return 0;
  }
  
  void deliverAnswer(DomainNotificationInfo& dni, const Answer& a, unsigned int usec)
  {
    d_freshness[dni.di.id]=a;
  }
  
  Resolver d_resolver;
};

void CommunicatorClass::addSlaveCheckRequest(const DomainInfo& di, const ComboAddress& remote)
{
  Lock l(&d_lock);
  DomainInfo ours = di;
  ours.backend = 0;
  d_tocheck.insert(ours);
  d_any_sem.post(); // kick the loop!
}

void CommunicatorClass::addTrySuperMasterRequest(DNSPacket *p)
{
  Lock l(&d_lock);
  DNSPacket ours = *p;
  d_potentialsupermasters.push_back(ours);
  d_any_sem.post(); // kick the loop!
}

void CommunicatorClass::slaveRefresh(PacketHandler *P)
{
  UeberBackend *B=dynamic_cast<UeberBackend *>(P->getBackend());
  vector<DomainInfo> rdomains;
  vector<DomainNotificationInfo > sdomains; // the bool is for 'presigned'
  vector<DNSPacket> trysuperdomains;
  
  {
    Lock l(&d_lock);
    rdomains.insert(rdomains.end(), d_tocheck.begin(), d_tocheck.end());
    d_tocheck.clear();
    trysuperdomains.insert(trysuperdomains.end(), d_potentialsupermasters.begin(), d_potentialsupermasters.end());
    d_potentialsupermasters.clear();
  }
  
  BOOST_FOREACH(DNSPacket& dp, trysuperdomains) {
    int res;
    res=P->trySuperMasterSynchronous(&dp);
    if(res>=0) {
      DNSPacket *r=dp.replyPacket();
      r->setRcode(res);
      r->setOpcode(Opcode::Notify);
      N->send(r);
      delete r;
    }
  }

  if(rdomains.empty()) // if we have priority domains, check them first
    B->getUnfreshSlaveInfos(&rdomains);
    
  DNSSECKeeper dk(B); // NOW HEAR THIS! This DK uses our B backend, so no interleaved access!
  {
    Lock l(&d_lock);
    typedef UniQueue::index<IDTag>::type domains_by_name_t;
    domains_by_name_t& nameindex=boost::multi_index::get<IDTag>(d_suckdomains);

    BOOST_FOREACH(DomainInfo& di, rdomains) {
      SuckRequest sr;
      sr.domain=di.zone;
      if(di.masters.empty()) // slave domains w/o masters are ignored
        continue;
      // remove unfresh domains already queued for AXFR, no sense polling them again
      sr.master=*di.masters.begin();
      if(nameindex.count(sr))
        continue;
      DomainNotificationInfo dni;
      dni.di=di;
      dni.dnssecOk = dk.isPresigned(di.zone);
      
      if(dk.getTSIGForAccess(di.zone, sr.master, &dni.tsigkeyname)) {
        string secret64;
        B->getTSIGKey(dni.tsigkeyname, &dni.tsigalgname, &secret64);
        B64Decode(secret64, dni.tsigsecret);
      }
      sdomains.push_back(dni);
    }
  }
  
  if(sdomains.empty())
  {
    if(d_slaveschanged) {
      Lock l(&d_lock);
      L<<Logger::Warning<<"No new unfresh slave domains, "<<d_suckdomains.size()<<" queued for AXFR already"<<endl;
    }
    d_slaveschanged = !rdomains.empty();
    return;
  }
  else {
    Lock l(&d_lock);
    L<<Logger::Warning<<sdomains.size()<<" slave domain"<<(sdomains.size()>1 ? "s" : "")<<" need"<<
      (sdomains.size()>1 ? "" : "s")<<
      " checking, "<<d_suckdomains.size()<<" queued for AXFR"<<endl;
  }
      
  SlaveSenderReceiver ssr;
  
  Inflighter<vector<DomainNotificationInfo>, SlaveSenderReceiver> ifl(sdomains, ssr);
  
  ifl.d_maxInFlight = 200;

  for(;;) {
    try {
      ifl.run();
      break;
    }
    catch(std::exception& e) {
      L<<Logger::Error<<"While checking domain freshness: " << e.what()<<endl;
    }
    catch(AhuException &re) {  
      L<<Logger::Error<<"While checking domain freshness: " << re.reason<<endl;
    }
  }
  L<<Logger::Warning<<"Received serial number updates for "<<ssr.d_freshness.size()<<" zones, had "<<ifl.getTimeouts()<<" timeouts"<<endl;

  typedef DomainNotificationInfo val_t;
  BOOST_FOREACH(val_t& val, sdomains) {
    DomainInfo& di(val.di);
    if(!di.backend) // might've come from the packethandler
      B->getDomainInfo(di.zone, di);
    if(!ssr.d_freshness.count(di.id)) 
      continue;
    uint32_t theirserial = ssr.d_freshness[di.id].theirSerial, ourserial = di.serial;
    
    if(rfc1982LessThan(theirserial, ourserial)) {
      L<<Logger::Error<<"Domain "<<di.zone<<" more recent than master, our serial " << ourserial << " > their serial "<< theirserial << endl;
      di.backend->setFresh(di.id);
    }
    else if(theirserial == ourserial) {
      if(!dk.isPresigned(di.zone)) {
        L<<Logger::Warning<<"Domain "<< di.zone<<" is fresh (not presigned, no RRSIG check)"<<endl;
        di.backend->setFresh(di.id);
      }
      else {
        B->lookup(QType(QType::RRSIG), di.zone); // can't use DK before we are done with this lookup!
        DNSResourceRecord rr;
        uint32_t maxExpire=0, maxInception=0;
        while(B->get(rr)) {
          RRSIGRecordContent rrc(rr.content);
          if(rrc.d_type == QType::SOA) {
            maxInception = std::max(maxInception, rrc.d_siginception);
            maxExpire = std::max(maxExpire, rrc.d_sigexpire);
          }
        }
        if(maxInception == ssr.d_freshness[di.id].theirInception && maxExpire == ssr.d_freshness[di.id].theirExpire) {
          L<<Logger::Warning<<"Domain "<< di.zone<<" is fresh and apex RRSIGs match"<<endl;
          di.backend->setFresh(di.id);
        }
        else {
          L<<Logger::Warning<<"Domain "<< di.zone<<" is fresh, but RRSIGS differ, so DNSSEC stale"<<endl;
          addSuckRequest(di.zone, *di.masters.begin());
        }
      }
    }
    else {
      L<<Logger::Warning<<"Domain "<< di.zone<<" is stale, master serial "<<theirserial<<", our serial "<< ourserial <<endl;
      addSuckRequest(di.zone, *di.masters.begin());
    }
  }
}  

// stub for PowerDNSLua linking
int directResolve(const std::string& qname, const QType& qtype, int qclass, vector<DNSResourceRecord>& ret)
{
  return -1;
}


