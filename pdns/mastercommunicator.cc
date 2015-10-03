/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2011  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation; 

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
#include <errno.h>
#include "communicator.hh"
#include <set>
#include <boost/utility.hpp>
#include <boost/foreach.hpp>
#include "dnsbackend.hh"
#include "ueberbackend.hh"
#include "packethandler.hh"
#include "nameserver.hh"
#include "resolver.hh"
#include "logger.hh"
#include "dns.hh"
#include "arguments.hh"
#include "packetcache.hh"
#include <boost/lexical_cast.hpp>

#include "namespaces.hh"


void CommunicatorClass::queueNotifyDomain(const DNSName &domain, UeberBackend *B)
{
  bool hasQueuedItem=false;
  set<string> nsset, ips;
  DNSResourceRecord rr;
  FindNS fns;

  B->lookup(QType(QType::NS),domain);
  while(B->get(rr))
    nsset.insert(rr.content);

  for(set<string>::const_iterator j=nsset.begin();j!=nsset.end();++j) {
    vector<string> nsips=fns.lookup(DNSName(*j), B);
    if(nsips.empty())
      L<<Logger::Warning<<"Unable to queue notification of domain '"<<domain<<"': nameservers do not resolve!"<<endl;
    else
      for(vector<string>::const_iterator k=nsips.begin();k!=nsips.end();++k) {
        const ComboAddress caIp(*k, 53);
        if(!d_preventSelfNotification || !AddressIsUs(caIp)) {
          if(!d_onlyNotify.match(&caIp))
            L<<Logger::Info<<"Skipped notification of domain '"<<domain<<"' to "<<*j<<" because it does not match only-notify."<<endl;
          else
            ips.insert(caIp.toStringWithPort());
        }
      }
  }

  for(set<string>::const_iterator j=ips.begin();j!=ips.end();++j) {
    L<<Logger::Warning<<"Queued notification of domain '"<<domain<<"' to "<<*j<<endl;
    d_nq.add(domain,*j);
    hasQueuedItem=true;
  }

  set<string> alsoNotify(d_alsoNotify);
  B->alsoNotifies(domain, &alsoNotify);

  for(set<string>::const_iterator j=alsoNotify.begin();j!=alsoNotify.end();++j) {
    try {
      const ComboAddress caIp(*j, 53);
      L<<Logger::Warning<<"Queued also-notification of domain '"<<domain<<"' to "<<caIp.toStringWithPort()<<endl;
      if (!ips.count(caIp.toStringWithPort())) {
        ips.insert(caIp.toStringWithPort());
        d_nq.add(domain, caIp.toStringWithPort());
      }
      hasQueuedItem=true;
    }
    catch(PDNSException &e) {
      L<<Logger::Warning<<"Unparseable IP in ALSO-NOTIFY metadata of domain '"<<domain<<"'. Warning: "<<e.reason<<endl;
    }
  }

  if (!hasQueuedItem)
    L<<Logger::Warning<<"Request to queue notification for domain '"<<domain<<"' was processed, but no valid nameservers or ALSO-NOTIFYs found. Not notifying!"<<endl;
}


bool CommunicatorClass::notifyDomain(const DNSName &domain)
{
  DomainInfo di;
  UeberBackend B;
  if(!B.getDomainInfo(domain, di)) {
    L<<Logger::Error<<"No such domain '"<<domain<<"' in our database"<<endl;
    return false;
  }
  queueNotifyDomain(domain, &B);
  // call backend and tell them we sent out the notification - even though that is premature    
  di.backend->setNotified(di.id, di.serial);

  return true; 
}

void NotificationQueue::dump()
{
  cerr<<"Waiting for notification responses: "<<endl;
  BOOST_FOREACH(NotificationRequest& nr, d_nqueue) {
    cerr<<nr.domain.toString()<<", "<<nr.ip<<endl;
  }
}

void CommunicatorClass::masterUpdateCheck(PacketHandler *P)
{
  if(!::arg().mustDo("master"))
    return; 

  UeberBackend *B=P->getBackend();
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
    PC.purge(i->zone.toString()); // fixes cvstrac ticket #30
    queueNotifyDomain(i->zone,P->getBackend());
    i->backend->setNotified(i->id,i->serial); 
  }
}

time_t CommunicatorClass::doNotifications()
{
  ComboAddress from;
  Utility::socklen_t fromlen;
  char buffer[1500];
  int size, sock;

  // receive incoming notifications on the nonblocking socket and take them off the list
  while(waitFor2Data(d_nsock4, d_nsock6, 0, 0, &sock) > 0) {
    fromlen=sizeof(from);
    size=recvfrom(sock,buffer,sizeof(buffer),0,(struct sockaddr *)&from,&fromlen);
    if(size < 0)
      break;
    DNSPacket p;

    p.setRemote(&from);

    if(p.parse(buffer,size)<0) {
      L<<Logger::Warning<<"Unable to parse SOA notification answer from "<<p.getRemote()<<endl;
      continue;
    }

    if(p.d.rcode)
      L<<Logger::Warning<<"Received unsuccessful notification report for '"<<p.qdomain<<"' from "<<from.toStringWithPort()<<", error: "<<RCode::to_s(p.d.rcode)<<endl;      

    if(d_nq.removeIf(from.toStringWithPort(), p.d.id, p.qdomain))
      L<<Logger::Warning<<"Removed from notification list: '"<<p.qdomain<<"' to "<<from.toStringWithPort()<<" "<< (p.d.rcode ? RCode::to_s(p.d.rcode) : "(was acknowledged)")<<endl;      
    else {
      L<<Logger::Warning<<"Received spurious notify answer for '"<<p.qdomain<<"' from "<< from.toStringWithPort()<<endl;
      //d_nq.dump();
    }
  }

  // send out possible new notifications
  DNSName domain;
  string ip;
  uint16_t id;

  bool purged;
  while(d_nq.getOne(domain, ip, &id, purged)) {
    if(!purged) {
      try {
        ComboAddress remote(ip, 53); // default to 53
        if((d_nsock6 < 0 && remote.sin4.sin_family == AF_INET6) ||
           (d_nsock4 < 0 && remote.sin4.sin_family == AF_INET))
             continue; // don't try to notify what we can't!
        if(d_preventSelfNotification && AddressIsUs(remote))
          continue;

        sendNotification(remote.sin4.sin_family == AF_INET ? d_nsock4 : d_nsock6, domain, remote, id); 
        drillHole(domain, ip);
      }
      catch(ResolverException &re) {
        L<<Logger::Error<<"Error trying to resolve '"+ip+"' for notifying '"+domain.toString()+"' to server: "+re.reason<<endl;
      }
    }
    else
      L<<Logger::Error<<Logger::NTLog<<"Notification for "<<domain<<" to "<<ip<<" failed after retries"<<endl;
  }

  return d_nq.earliest();
}

void CommunicatorClass::sendNotification(int sock, const DNSName& domain, const ComboAddress& remote, uint16_t id)
{
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, domain, QType::SOA, 1, Opcode::Notify);
  pw.getHeader()->id = id;
  pw.getHeader()->aa = true; 

  if(sendto(sock, &packet[0], packet.size(), 0, (struct sockaddr*)(&remote), remote.getSocklen()) < 0) {
    throw ResolverException("Unable to send notify to "+remote.toStringWithPort()+": "+stringerror());
  }
}

void CommunicatorClass::drillHole(const DNSName &domain, const string &ip)
{
  Lock l(&d_holelock);
  d_holes[make_pair(domain,ip)]=time(0);
}

bool CommunicatorClass::justNotified(const DNSName &domain, const string &ip)
{
  Lock l(&d_holelock);
  if(d_holes.find(make_pair(domain,ip))==d_holes.end()) // no hole
    return false;

  if(d_holes[make_pair(domain,ip)]>time(0)-900)    // recent hole
    return true;

  // do we want to purge this? XXX FIXME 
  return false;
}

void CommunicatorClass::makeNotifySockets()
{
  d_nsock4 = makeQuerySocket(ComboAddress(::arg()["query-local-address"]), true);
  if(!::arg()["query-local-address6"].empty())
    d_nsock6 = makeQuerySocket(ComboAddress(::arg()["query-local-address6"]), true);
  else
    d_nsock6 = -1;
}

void CommunicatorClass::notify(const DNSName &domain, const string &ip)
{
  d_nq.add(domain, ip);
  d_any_sem.post();
}

