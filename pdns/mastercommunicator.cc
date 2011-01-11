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
#include <boost/lexical_cast.hpp>

#include "namespaces.hh"

// class that one day might be more than a function to help you get IP addresses for a nameserver
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
      L<<Logger::Warning<<"Received unsuccessful notification report for '"<<p.qdomain<<"' from "<<p.getRemote()<<", rcode: "<<p.d.rcode<<endl;      
    
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

