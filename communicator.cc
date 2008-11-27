/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2008  PowerDNS.COM BV

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
#include <boost/lexical_cast.hpp>

using namespace boost;

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

class FindNS
{
public:
  vector<string>lookup(const string &name, DNSBackend *B)
  {
    vector<string>addresses;
    struct hostent *h;
    h=gethostbyname(name.c_str());

    if(h) {
      for(char **h_addr_list=h->h_addr_list;*h_addr_list;++h_addr_list) {
	ostringstream os;
	unsigned char *p=reinterpret_cast<unsigned char *>(*h_addr_list);
	os<<(int)*p++<<".";
	os<<(int)*p++<<".";
	os<<(int)*p++<<".";
	os<<(int)*p++;

	addresses.push_back(os.str());
      }
    }

    B->lookup(QType(QType::A),name);
    DNSResourceRecord rr;
    while(B->get(rr)) 
      addresses.push_back(rr.content);   // SOL if you have a CNAME for an NS

    return addresses;
  }
}d_fns;

void CommunicatorClass::queueNotifyDomain(const string &domain, DNSBackend *B)
{
  set<string> ips;
  
  DNSResourceRecord rr;
  set<string>nsset;

  B->lookup(QType(QType::NS),domain);
  while(B->get(rr)) 
    nsset.insert(rr.content);
  
  for(set<string>::const_iterator j=nsset.begin();j!=nsset.end();++j) {
    vector<string>nsips=d_fns.lookup(*j, B);
    if(nsips.empty())
      L<<Logger::Warning<<"Unable to queue notification of domain '"<<domain<<"': nameservers do not resolve!"<<endl;
    for(vector<string>::const_iterator k=nsips.begin();k!=nsips.end();++k)
      ips.insert(*k);
  }
  
  // make calls to d_nq.add(domain, ip);
  for(set<string>::const_iterator j=ips.begin();j!=ips.end();++j) {
    L<<Logger::Warning<<"Queued notification of domain '"<<domain<<"' to "<<*j<<endl;
    d_nq.add(domain,*j);
  }
  
  set<string>alsoNotify;
  B->alsoNotifies(domain, &alsoNotify);
  
  for(set<string>::const_iterator j=alsoNotify.begin();j!=alsoNotify.end();++j) {
    L<<Logger::Warning<<"Queued also-notification of domain '"<<domain<<"' to "<<*j<<endl;
    d_nq.add(domain,*j);
  }
}

bool CommunicatorClass::notifyDomain(const string &domain)
{
  DomainInfo di;
  PacketHandler P;
  if(!P.getBackend()->getDomainInfo(domain, di)) {
    L<<Logger::Error<<"No such domain '"<<domain<<"' in our database"<<endl;
    return false;
  }
  queueNotifyDomain(domain, P.getBackend());
  // call backend and tell them we sent out the notification - even though that is premature    
  di.backend->setNotified(di.id, di.serial);

  return true; 
}


void CommunicatorClass::masterUpdateCheck(PacketHandler *P)
{
  if(!::arg().mustDo("master"))
    return; 

  UeberBackend *B=dynamic_cast<UeberBackend *>(P->getBackend());
  vector<DomainInfo> cmdomains;
  B->getUpdatedMasters(&cmdomains);
  
  if(cmdomains.empty()) {
    if(d_masterschanged)
      L<<Logger::Warning<<"No master domains need notifications"<<endl;
    d_masterschanged=false;
  }
  else {
    d_masterschanged=true;
    L<<Logger::Error<<cmdomains.size()<<" domain"<<(cmdomains.size()>1 ? "s" : "")<<" for which we are master need"<<
      (cmdomains.size()>1 ? "" : "s")<<
      " notifications"<<endl;
  }

  // figure out A records of everybody needing notification
  // do this via the FindNS class, d_fns
  
  for(vector<DomainInfo>::const_iterator i=cmdomains.begin();i!=cmdomains.end();++i) {
    extern PacketCache PC;
    vector<string> topurge;
    topurge.push_back(i->zone);
    PC.purge(topurge); // fixes cvstrac ticket #30
    queueNotifyDomain(i->zone,P->getBackend());
    i->backend->setNotified(i->id,i->serial); 
  }
}

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
  map<string, int> skipMasters;
  for(vector<DomainInfo>::iterator i=sdomains.begin();i!=sdomains.end();++i) {
    Resolver resolver;   
    resolver.makeUDPSocket();  
    d_slaveschanged=true;
    uint32_t ourserial=i->serial, theirserial=0;
    
    if(d_havepriosuckrequest) {
      d_havepriosuckrequest=false;
      break;
    }

    random_shuffle(i->masters.begin(), i->masters.end());
    for(vector<string>::const_iterator iter = i->masters.begin(); iter != i->masters.end(); ++iter) {
      try {
	if(skipMasters[*iter] > 5)
	  throw AhuException("Skipping query to '"+*iter+"' because of previous timeouts in this cycle");
	
	resolver.getSoaSerial(*iter, i->zone, &theirserial);
	skipMasters[*iter]=0;	
	if(theirserial<i->serial) {
	  L<<Logger::Error<<"Domain "<<i->zone<<" more recent than master, our serial "<<ourserial<<" > their serial "<<theirserial<<endl;
	  i->backend->setFresh(i->id);
	}
	else if(theirserial==i->serial) {
	  L<<Logger::Warning<<"Domain "<<i->zone<<" is fresh"<<endl;
	  i->backend->setFresh(i->id);
	}
	else {
	  L<<Logger::Warning<<"Domain "<<i->zone<<" is stale, master serial "<<theirserial<<", our serial "<<i->serial<<endl;
	  addSuckRequest(i->zone, *iter);
	}
	break;
      }
      catch(ResolverException &re) {
	if(re.reason.find("Timeout") != string::npos)
	  skipMasters[*iter]++;

	L<<Logger::Error<<"Error trying to retrieve/refresh '"+i->zone+"': "+re.reason<<endl;
	if(next(iter) != i->masters.end()) 
	  L<<Logger::Error<<"Trying next master '"<<*next(iter)<<"' for '"+i->zone+"'"<<endl;
      }
      catch(AhuException &re) {
	L<<Logger::Error<<"Error trying to retrieve/refresh '"+i->zone+"': "+re.reason<<endl;
	if(next(iter) != i->masters.end()) 
	  L<<Logger::Error<<"Trying next master '"<<*next(iter)<<"' for '"+i->zone+"'"<<endl;
      }
    }
  }
}  

time_t CommunicatorClass::doNotifications()
{
  ComboAddress from;
  Utility::socklen_t fromlen=sizeof(from);
  char buffer[1500];
  int size;
  static Resolver d_nresolver;
  // receive incoming notifications on the nonblocking socket and take them off the list

  while((size=recvfrom(d_nsock,buffer,sizeof(buffer),0,(struct sockaddr *)&from,&fromlen))>0) {
    DNSPacket p;

    p.setRemote(&from);

    if(p.parse(buffer,size)<0) {
      L<<Logger::Warning<<"Unable to parse SOA notification answer from "<<p.getRemote()<<endl;
      continue;
    }

    if(p.d.rcode)
      L<<Logger::Warning<<"Received unsuccesful notification report for '"<<p.qdomain<<"' from "<<p.getRemote()<<", rcode: "<<p.d.rcode<<endl;      
    
    if(d_nq.removeIf(p.getRemote(), p.d.id, p.qdomain))
      L<<Logger::Warning<<"Removed from notification list: '"<<p.qdomain<<"' to "<<p.getRemote()<< (p.d.rcode ? "" : " (was acknowledged)")<<endl;      
    else
      L<<Logger::Warning<<"Received spurious notify answer for '"<<p.qdomain<<"' from "<<p.getRemote()<<endl;      
  }

  // send out possible new notifications
  string domain, ip;
  uint16_t id;

  bool purged;
  while(d_nq.getOne(domain, ip, &id, purged)) {
    if(!purged) {
      try {
	d_nresolver.notify(d_nsock, domain, ip, id);
	drillHole(domain, ip);
      }
      catch(ResolverException &re) {
	L<<Logger::Error<<"Error trying to resolve '"+ip+"' for notifying '"+domain+"' to server: "+re.reason<<endl;
      }
    }
    else
      L<<Logger::Error<<Logger::NTLog<<"Notification for "<<domain<<" to "<<ip<<" failed after retries"<<endl;
  }

  return d_nq.earliest();
}

void CommunicatorClass::drillHole(const string &domain, const string &ip)
{
  Lock l(&d_holelock);
  d_holes[make_pair(domain,ip)]=time(0);
}

bool CommunicatorClass::justNotified(const string &domain, const string &ip)
{
  Lock l(&d_holelock);
  if(d_holes.find(make_pair(domain,ip))==d_holes.end()) // no hole
    return false;

  if(d_holes[make_pair(domain,ip)]>time(0)-900)    // recent hole
    return true;

  // do we want to purge this? XXX FIXME 
  return false;
}

void CommunicatorClass::makeNotifySocket()
{
  if((d_nsock=socket(AF_INET, SOCK_DGRAM,0))<0)
    throw AhuException(string("notification socket: ")+strerror(errno));

  struct sockaddr_in sin;
  memset((char *)&sin,0, sizeof(sin));
  
  sin.sin_family = AF_INET;

  // Bind to a specific IP (query-local-address) if specified
  string querylocaladdress(::arg()["query-local-address"]);
  if (querylocaladdress=="") {
    sin.sin_addr.s_addr = INADDR_ANY;
  }
  else
  {
    struct hostent *h=0;
    h=gethostbyname(querylocaladdress.c_str());
    if(!h) {
      Utility::closesocket(d_nsock);
      d_nsock=-1;	
      throw AhuException("Unable to resolve query local address");
    }

    sin.sin_addr.s_addr = *(int*)h->h_addr;
  }
  
  int n=0;
  for(;n<10;n++) {
    sin.sin_port = htons(10000+(Utility::random()%50000));
    
    if(::bind(d_nsock, (struct sockaddr *)&sin, sizeof(sin)) >= 0) 
      break;
  }
  if(n==10) {
    Utility::closesocket(d_nsock);
    d_nsock=-1;
    throw AhuException(string("binding notify socket: ")+strerror(errno));
  }
  if( !Utility::setNonBlocking( d_nsock ))
    throw AhuException(string("error getting or setting notify socket non-blocking: ")+strerror(errno));

}

void CommunicatorClass::notify(const string &domain, const string &ip)
{
  d_nq.add(domain, ip);

  d_any_sem.post();
}

void CommunicatorClass::mainloop(void)
{
  try {
#ifndef WIN32
    signal(SIGPIPE,SIG_IGN);
#endif // WIN32
    L<<Logger::Error<<"Master/slave communicator launching"<<endl;
    PacketHandler P;
    d_tickinterval=::arg().asNum("slave-cycle-interval");
    makeNotifySocket();

    int rc;
    time_t next;

    time_t tick;

    for(;;) {
      slaveRefresh(&P);
      masterUpdateCheck(&P);

      tick=min(doNotifications(),
	       d_tickinterval);

      //      L<<Logger::Error<<"tick = "<<tick<<", d_tickinterval = "<<d_tickinterval<<endl;
      next=time(0)+tick;

      while(time(0) < next) {
	rc=d_any_sem.tryWait();

	if(rc)
	  Utility::sleep(1);
	else { 
	  if(!d_suck_sem.tryWait()) {
	    SuckRequest sr;
	    {
	      Lock l(&d_lock);
	      sr=d_suckdomains.front();
	      d_suckdomains.pop_front();
	    }
	    suck(sr.domain,sr.master);
	  }
	}
	// this gets executed at least once every second
	doNotifications();
      }
    }
  }
  catch(AhuException &ae) {
    L<<Logger::Error<<"Communicator thread died because of error: "<<ae.reason<<endl;
    Utility::sleep(1);
    exit(0);
  }
  catch(std::exception &e) {
    L<<Logger::Error<<"Communicator thread died because of STL error: "<<e.what()<<endl;
    exit(0);
  }
  catch( ... )
  {
    L << Logger::Error << "Communicator caught unknown exception." << endl;
    exit( 0 );
  }
}

