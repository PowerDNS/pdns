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
#include "inflighter.cc"

#include "namespaces.hh"

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
  PacketHandler P;

  DomainInfo di;
  di.backend=0;
  bool first=true;    
  try {
    Resolver resolver;
    resolver.axfr(remote, domain.c_str());

    UeberBackend *B=dynamic_cast<UeberBackend *>(P.getBackend());
    NSEC3PARAMRecordContent ns3pr;
    bool narrow;
    DNSSECKeeper dk;
    bool dnssecZone = false;
    bool haveNSEC3=false;
    if(dk.haveActiveKSKFor(domain)) {
      dnssecZone=true;
      haveNSEC3=dk.getNSEC3PARAM(domain, &ns3pr, &narrow);
      string hashed;
      if(!haveNSEC3) 
        cerr<<"Adding NSEC ordering information"<<endl;
      else if(!narrow)
        cerr<<"Adding NSEC3 hashed ordering information for '"<<domain<<"'"<<endl;
      else 
        cerr<<"Erasing NSEC3 ordering since we are narrow, only setting 'auth' fields"<<endl;
    }

    if(!B->getDomainInfo(domain, di) || !di.backend) {
      L<<Logger::Error<<"Can't determine backend for domain '"<<domain<<"'"<<endl;
      return;
    }
    domain_id=di.id;

    Resolver::res_t recs;
    set<string> nsset, qnames;
    while(resolver.axfrChunk(recs)) {
      if(first) {
        L<<Logger::Error<<"AXFR started for '"<<domain<<"', transaction started"<<endl;
        di.backend->startTransaction(domain, domain_id);
        first=false;
      }
      
      for(Resolver::res_t::iterator i=recs.begin();i!=recs.end();++i) {
        if(!endsOn(i->qname, domain)) { 
          L<<Logger::Error<<"Remote "<<remote<<" tried to sneak in out-of-zone data '"<<i->qname<<"' during AXFR of zone '"<<domain<<"', ignoring"<<endl;
          continue;
        }
        if(dnssecZone) {
          if(i->qtype.getCode() == QType::NS && !pdns_iequals(i->qname, domain)) 
            nsset.insert(i->qname);
          qnames.insert(i->qname);
        }  
        i->domain_id=domain_id;
        if(i->qtype.getCode()>=1024)
          throw DBException("Database can't store unknown record type "+lexical_cast<string>(i->qtype.getCode()-1024));

        di.backend->feedRecord(*i);
      }
    }
    if(dnssecZone) {
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
      
        if(!haveNSEC3) // NSEC
          di.backend->updateDNSSECOrderAndAuth(domain_id, domain, qname, auth);
        else {
          if(!narrow) {
            hashed=toLower(toBase32Hex(hashQNameWithSalt(ns3pr.d_iterations, ns3pr.d_salt, qname)));
            cerr<<"'"<<qname<<"' -> '"<< hashed <<"'"<<endl;
          }
          di.backend->updateDNSSECOrderAndAuthAbsolute(domain_id, qname, hashed, auth);
        }
      }
    }
    
    di.backend->commitTransaction();
    di.backend->setFresh(domain_id);
    L<<Logger::Error<<"AXFR done for '"<<domain<<"', zone committed"<<endl;
  }
  catch(DBException &re) {
    L<<Logger::Error<<"Unable to feed record during incoming AXFR of '"+domain+"': "<<re.reason<<endl;
    if(di.backend && !first) {
      L<<Logger::Error<<"Aborting possible open transaction for domain '"<<domain<<"' AXFR"<<endl;
      di.backend->abortTransaction();
    }
  }
  catch(ResolverException &re) {
    L<<Logger::Error<<"Unable to AXFR zone '"+domain+"' from remote '"<<remote<<"': "<<re.reason<<endl;
    if(di.backend && !first) {
      L<<Logger::Error<<"Aborting possible open transaction for domain '"<<domain<<"' AXFR"<<endl;
      di.backend->abortTransaction();
    }
  }
}
struct QueryInfo
  {
    struct timeval query_ttd;
    uint16_t id;
  };

struct SlaveSenderReceiver
{
  typedef pair<string, uint16_t> Identifier;
  typedef uint32_t Answer;
  
  map<uint32_t, uint32_t> d_serials;
  
  SlaveSenderReceiver()
  {
    d_resolver.makeUDPSocket();
  }
  
  void deliverTimeout(const Identifier& i)
  {}
  
  Identifier send(DomainInfo& di)
  {
    random_shuffle(di.masters.begin(), di.masters.end());
    return make_pair(di.zone, d_resolver.sendResolve(*di.masters.begin(), di.zone.c_str(), QType::SOA));
  }
  
  bool receive(Identifier& id, Answer& a)
  {
    if(d_resolver.tryGetSOASerial(&id.first, &a, &id.second)) {
      return 1;
    }
    return 0;
  }
  
  void deliverAnswer(DomainInfo& i, uint32_t serial, unsigned int usec)
  {
    d_serials[i.id]=serial;
  }
  
  Resolver d_resolver;

};

void CommunicatorClass::slaveRefresh(PacketHandler *P)
{
  UeberBackend *B=dynamic_cast<UeberBackend *>(P->getBackend());
  vector<DomainInfo> sdomains, rdomains;
  B->getUnfreshSlaveInfos(&rdomains);
  
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
      sdomains.push_back(di);
    }
//    cerr<<rdomains.size() - sdomains.size()<<" prevented"<<endl;  
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
  Inflighter<vector<DomainInfo>, SlaveSenderReceiver> ifl(sdomains, ssr);
  
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
  L<<Logger::Warning<<"Received serial number updates for "<<ssr.d_serials.size()<<" zones"<<endl;

  BOOST_FOREACH(DomainInfo& di, sdomains) {
    if(!ssr.d_serials.count(di.id)) 
      continue;
    uint32_t theirserial = ssr.d_serials[di.id], ourserial = di.serial;
    
    if(theirserial < ourserial) {
      L<<Logger::Error<<"Domain "<<di.zone<<" more recent than master, our serial " << ourserial << " > their serial "<< theirserial << endl;
      di.backend->setFresh(di.id);
    }
    else if(theirserial == ourserial) {
      L<<Logger::Warning<<"Domain "<< di.zone<<" is fresh"<<endl;
      di.backend->setFresh(di.id);
    }
    else {
      L<<Logger::Warning<<"Domain "<< di.zone<<" is stale, master serial "<<theirserial<<", our serial "<< ourserial <<endl;
      addSuckRequest(di.zone, *di.masters.begin());
    }
  }
}  

