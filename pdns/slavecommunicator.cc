/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2009  PowerDNS.COM BV

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

// #include "namespaces.hh"

void CommunicatorClass::addSuckRequest(const string &domain, const string &master, bool priority)
{
  Lock l(&d_lock);
  
  SuckRequest sr;
  sr.domain = domain;
  sr.master = master;

  if(priority) {
    d_suckdomains.push_front(sr);
    //  d_havepriosuckrequest=true;
  }
  else 
    d_suckdomains.push_back(sr);
  
  d_suck_sem.post();
  d_any_sem.post();
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

    if(!B->getDomainInfo(domain, di) || !di.backend) {
      L<<Logger::Error<<"Can't determine backend for domain '"<<domain<<"'"<<endl;
      return;
    }
    domain_id=di.id;

    Resolver::res_t recs;

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
        i->domain_id=domain_id;
        if(i->qtype.getCode()>=1024)
          throw DBException("Database can't store unknown record type "+lexical_cast<string>(i->qtype.getCode()-1024));

        di.backend->feedRecord(*i);
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
  
  void deliverAnswer(DomainInfo& i, uint32_t serial)
  {
    d_serials[i.id]=serial;
  }
  
  Resolver d_resolver;

};

void CommunicatorClass::slaveRefresh(PacketHandler *P)
{
  UeberBackend *B=dynamic_cast<UeberBackend *>(P->getBackend());
  vector<DomainInfo> sdomains;
  B->getUnfreshSlaveInfos(&sdomains);
  if(sdomains.empty())
  {
    if(d_slaveschanged)
      L<<Logger::Warning<<"All slave domains are fresh"<<endl;
    d_slaveschanged=false;
    return;
  }
  else 
    L<<Logger::Warning<<sdomains.size()<<" slave domain"<<(sdomains.size()>1 ? "s" : "")<<" need"<<
      (sdomains.size()>1 ? "" : "s")<<
      " checking"<<endl;
      
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

