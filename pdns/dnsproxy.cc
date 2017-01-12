/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "packetcache.hh"
#include "utility.hh"
#include "dnsproxy.hh"
#include "pdnsexception.hh"
#include <sys/types.h>
#include <errno.h>
#include "dns.hh"
#include "logger.hh"
#include "statbag.hh"
#include "dns_random.hh"

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
    throw PDNSException(string("socket: ")+strerror(errno));
 
  ComboAddress local;
  if(remaddr.sin4.sin_family==AF_INET)
    local = ComboAddress("0.0.0.0");
  else
    local = ComboAddress("::");
    
  int n=0;
  for(;n<10;n++) {
    local.sin4.sin_port = htons(10000+dns_random(50000));
    
    if(::bind(d_sock, (struct sockaddr *)&local, local.getSocklen()) >= 0) 
      break;
  }
  if(n==10) {
    closesocket(d_sock);
    d_sock=-1;
    throw PDNSException(string("binding dnsproxy socket: ")+strerror(errno));
  }

  if(connect(d_sock, (sockaddr *)&remaddr, remaddr.getSocklen())<0) 
    throw PDNSException("Unable to UDP connect to remote nameserver "+remaddr.toStringWithPort()+": "+stringerror());

  d_xor=dns_random(0xffff);
  L<<Logger::Error<<"DNS Proxy launched, local port "<<ntohs(local.sin4.sin_port)<<", remote "<<remaddr.toStringWithPort()<<endl;
} 

void DNSProxy::go()
{
  pthread_t tid;
  pthread_create(&tid,0,&launchhelper,this);
}


void DNSProxy::onlyFrom(const string &ips)
{
  d_ng.toMasks(ips);
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
    ce.anyLocal = p->d_anyLocal;
    ce.complete=0;
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

//! look up qname aname with r->qtype, plonk it in the answer section of 'r' with name target
bool DNSProxy::completePacket(DNSPacket *r, const DNSName& target,const DNSName& aname)
{
  uint16_t id;
  {
    Lock l(&d_lock);
    id=getID_locked();

    ConntrackEntry ce;
    ce.id       = r->d.id;
    ce.remote =   r->d_remote;
    ce.outsock  = r->getSocket();
    ce.created  = time( NULL );
    ce.qtype = r->qtype.getCode();
    ce.qname = target;
    ce.anyLocal = r->d_anyLocal;
    ce.complete = r;
    ce.aname=aname;
    d_conntrack[id]=ce;
  }

  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, target, r->qtype.getCode());
  pw.getHeader()->rd=true;
  pw.getHeader()->id=id ^ d_xor;

  if(send(d_sock,&packet[0], packet.size() , 0)<0) { // zoom
    L<<Logger::Error<<"Unable to send a packet to our recursing backend: "<<stringerror()<<endl;
  }

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
      if(i->second.created) {
        L<<Logger::Warning<<"Recursive query for remote "<<
          i->second.remote.toStringWithPort()<<" with internal id "<<n<<
          " was not answered by backend within timeout, reusing id"<<endl;
	delete i->second.complete;
	S.inc("recursion-unanswered");
      }
      return n;
    }
  }
}

void DNSProxy::mainloop(void)
{
  try {
    char buffer[1500];
    ssize_t len;

    struct msghdr msgh;
    struct iovec iov;
    char cbuf[256];

    for(;;) {
      len=recv(d_sock, buffer, sizeof(buffer),0); // answer from our backend
      if(len<(ssize_t)sizeof(dnsheader)) {
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
#if BYTE_ORDER == BIG_ENDIAN
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

        DNSPacket p(false),q(false);
        p.parse(buffer,(size_t)len);
        q.parse(buffer,(size_t)len);

        if(p.qtype.getCode() != i->second.qtype || p.qdomain != i->second.qname) {
          L<<Logger::Error<<"Discarding packet from recursor backend with id "<<(d.id^d_xor)<<
            ", qname or qtype mismatch ("<<p.qtype.getCode()<<" v " <<i->second.qtype<<", "<<p.qdomain<<" v "<<i->second.qname<<")"<<endl;
          continue;
        }

        /* Set up iov and msgh structures. */
        memset(&msgh, 0, sizeof(struct msghdr));
	string reply; // needs to be alive at time of sendmsg!
	if(i->second.complete) {

	  MOADNSParser mdp(false, p.getString());
	  //	  cerr<<"Got completion, "<<mdp.d_answers.size()<<" answers, rcode: "<<mdp.d_header.rcode<<endl;
	  for(MOADNSParser::answers_t::const_iterator j=mdp.d_answers.begin(); j!=mdp.d_answers.end(); ++j) {        
	    //	    cerr<<"comp: "<<(int)j->first.d_place-1<<" "<<j->first.d_label<<" " << DNSRecordContent::NumberToType(j->first.d_type)<<" "<<j->first.d_content->getZoneRepresentation()<<endl;
	    if(j->first.d_place == DNSResourceRecord::ANSWER || (j->first.d_place == DNSResourceRecord::AUTHORITY && j->first.d_type == QType::SOA)) {
	    
	      DNSResourceRecord rr;

	      if(j->first.d_type == i->second.qtype || (i->second.qtype == QType::ANY && (j->first.d_type == QType::A || j->first.d_type == QType::AAAA))) {
		rr.qname=i->second.aname;
		rr.qtype = j->first.d_type;
		rr.ttl=j->first.d_ttl;
		rr.d_place= j->first.d_place;
		rr.content=j->first.d_content->getZoneRepresentation();
		i->second.complete->addRecord(rr);
	      }
	    }
	  }
	  i->second.complete->setRcode(mdp.d_header.rcode);
	  reply=i->second.complete->getString();
	  iov.iov_base = (void*)reply.c_str();
	  iov.iov_len = reply.length();
	  delete i->second.complete;
	  i->second.complete=0;
	}
	else {
	  iov.iov_base = buffer;
	  iov.iov_len = len;
	}
        msgh.msg_iov = &iov;
        msgh.msg_iovlen = 1;
        msgh.msg_name = (struct sockaddr*)&i->second.remote;
        msgh.msg_namelen = i->second.remote.getSocklen();
        msgh.msg_control=NULL;

        if(i->second.anyLocal) {
          addCMsgSrcAddr(&msgh, cbuf, i->second.anyLocal.get_ptr(), 0);
        }
        if(sendmsg(i->second.outsock, &msgh, 0) < 0)
          L<<Logger::Warning<<"dnsproxy.cc: Error sending reply with sendmsg (socket="<<i->second.outsock<<"): "<<strerror(errno)<<endl;
        
        PC.insert(&q, &p, true);
        i->second.created=0;
      }
    }
  }
  catch(PDNSException &ae) {
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

DNSProxy::~DNSProxy() {
  if (d_sock>-1) closesocket(d_sock);
  d_sock=-1;
}
