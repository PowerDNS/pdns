/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2004 - 2008 PowerDNS.COM BV

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
#include "dnsproxy.hh"
#include "ahuexception.hh"
#include <sys/types.h>
#include <errno.h>
#include "dns.hh"
#include "logger.hh"
#include "statbag.hh"


extern StatBag S;
extern PacketCache PC;

DNSProxy::DNSProxy(const string &remote)
{
  pthread_mutex_init(&d_lock,0);
  d_resanswers=S.getPointer("recursing-answers");
  d_resquestions=S.getPointer("recursing-questions");
  d_udpanswers=S.getPointer("udp-answers");
  ComboAddress remaddr(remote, 53);
  
  if((d_sock=socket(remaddr.sin4.sin_family, SOCK_DGRAM,0))<0)
    throw AhuException(string("socket: ")+strerror(errno));
 
  ComboAddress local;
  if(remaddr.sin4.sin_family==AF_INET)
    local = ComboAddress("0.0.0.0");
  else
    local = ComboAddress("::");
    
  int n=0;
  for(;n<10;n++) {
    local.sin4.sin_port = htons(10000+( Utility::random()%50000));
    
    if(::bind(d_sock, (struct sockaddr *)&local, local.getSocklen()) >= 0) 
      break;
  }
  if(n==10) {
    Utility::closesocket(d_sock);
    d_sock=-1;
    throw AhuException(string("binding dnsproxy socket: ")+strerror(errno));
  }

  if(connect(d_sock, (sockaddr *)&remaddr, remaddr.getSocklen())<0) 
    throw AhuException("Unable to UDP connect to remote nameserver "+remaddr.toStringWithPort()+": "+stringerror());

  d_xor=Utility::random()&0xffff;
  L<<Logger::Error<<"DNS Proxy launched, local port "<<ntohs(local.sin4.sin_port)<<", remote "<<remaddr.toStringWithPort()<<endl;
} 

void DNSProxy::go()
{
  pthread_t tid;
  pthread_create(&tid,0,&launchhelper,this);
}


void DNSProxy::onlyFrom(const string &ips)
{
  vector<string>parts;
  stringtok(parts,ips,", \t");
  for(vector<string>::const_iterator i=parts.begin();
      i!=parts.end();++i)
    d_ng.addMask(*i);
  
}

bool DNSProxy::recurseFor(DNSPacket* p)
{
  return d_ng.match((ComboAddress *)&p->d_remote);
}

/** returns false if p->remote is not allowed to recurse via us */
bool DNSProxy::sendPacket(DNSPacket *p)
{
  if(!recurseFor(p))
    return false;

  uint16_t id;
  {
    Lock l(&d_lock);
    id=getID_locked();

    ConntrackEntry ce;
    ce.id       = p->d.id;
    ce.remote = p->d_remote;
    ce.outsock  = p->getSocket();
    ce.created  = time( NULL );
    ce.qtype = p->qtype.getCode();
    ce.qname = p->qdomain;
    d_conntrack[id]=ce;
  }
  p->d.id=id^d_xor;
  p->commitD();
  
  const string& buffer = p->getString();
  
  if(send(d_sock,buffer.c_str(), buffer.length() , 0)<0) { // zoom
    L<<Logger::Error<<"Unable to send a packet to our recursing backend: "<<stringerror()<<endl;
  }
  (*d_resquestions)++;
  return true;

}
/** This finds us an unused or stale ID. Does not actually clean the contents */
int DNSProxy::getID_locked()
{
  map_t::iterator i;
  for(int n=0;;++n) {
    i=d_conntrack.find(n);
    if(i==d_conntrack.end()) {
      return n;
    }
    else if(i->second.created<time(0)-60) {
      if(i->second.created)
        L<<Logger::Warning<<"Recursive query for remote "<<
          i->second.remote.toStringWithPort()<<" with internal id "<<n<<
          " was not answered by backend within timeout, reusing id"<<endl;
      
      return n;
    }
  }
}

void DNSProxy::mainloop(void)
{
  try {
    char buffer[1500];
    int len;

    for(;;) {
      len=recv(d_sock, buffer, sizeof(buffer),0); // answer from our backend
      if(len<12) {
        if(len<0)
          L<<Logger::Error<<"Error receiving packet from recursor backend: "<<stringerror()<<endl;
        else if(len==0)
          L<<Logger::Error<<"Error receiving packet from recursor backend, EOF"<<endl;
        else
          L<<Logger::Error<<"Short packet from recursor backend, "<<len<<" bytes"<<endl;
        
        continue;
      }
      (*d_resanswers)++;
      (*d_udpanswers)++;
      dnsheader d;
      memcpy(&d,buffer,sizeof(d));
      {
        Lock l(&d_lock);
#ifdef WORDS_BIGENDIAN
        // this is needed because spoof ID down below does not respect the native byteorder
        d.id = ( 256 * (uint16_t)buffer[1] ) + (uint16_t)buffer[0];  
#endif
        map_t::iterator i=d_conntrack.find(d.id^d_xor);
        if(i==d_conntrack.end()) {
          L<<Logger::Error<<"Discarding untracked packet from recursor backend with id "<<(d.id^d_xor)<<
            ". Conntrack table size="<<d_conntrack.size()<<endl;
          continue;
        }
        else if(i->second.created==0) {
          L<<Logger::Error<<"Received packet from recursor backend with id "<<(d.id^d_xor)<<" which is a duplicate"<<endl;
          continue;
        }
        d.id=i->second.id;
        memcpy(buffer,&d,sizeof(d));  // commit spoofed id

        DNSPacket p,q;
        p.parse(buffer,len);
        q.parse(buffer,len);

        if(p.qtype.getCode() != i->second.qtype || p.qdomain != i->second.qname) {
          L<<Logger::Error<<"Discarding packet from recursor backend with id "<<(d.id^d_xor)<<
            ", qname or qtype mismatch"<<endl;
          continue;
        }
        sendto(i->second.outsock, buffer, len, 0, (struct sockaddr*)&i->second.remote, i->second.remote.getSocklen());
        
        PC.insert(&q, &p);
        i->second.created=0;
      }
    }
  }
  catch(AhuException &ae) {
    L<<Logger::Error<<"Fatal error in DNS proxy: "<<ae.reason<<endl;
  }
  catch(std::exception &e) {
    L<<Logger::Error<<"Communicator thread died because of STL error: "<<e.what()<<endl;
  }
  catch( ... )
  {
    L << Logger::Error << "Caught unknown exception." << endl;
  }
  L<<Logger::Error<<"Exiting because DNS proxy failed"<<endl;
  exit(1);
}
