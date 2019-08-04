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
#include "dns.hh"
#include "logger.hh"
#include "statbag.hh"
#include "dns_random.hh"
#include "stubresolver.hh"
#include "arguments.hh"
#include "threadname.hh"

extern StatBag S;

DNSProxy::DNSProxy(const string &remote)
{
  pthread_mutex_init(&d_lock,0);
  d_resanswers=S.getPointer("recursing-answers");
  d_resquestions=S.getPointer("recursing-questions");
  d_udpanswers=S.getPointer("udp-answers");

  vector<string> addresses;
  stringtok(addresses, remote, " ,\t");
  d_remote = ComboAddress(addresses[0], 53);

  if((d_sock=socket(d_remote.sin4.sin_family, SOCK_DGRAM,0))<0) {
    throw PDNSException(string("socket: ")+stringerror());
  }

  ComboAddress local;
  if(d_remote.sin4.sin_family==AF_INET) {
    local = ComboAddress("0.0.0.0");
  }
  else {
    local = ComboAddress("::");
  }
    
  unsigned int n=0;
  for(;n<10;n++) {
    local.sin4.sin_port = htons(10000+dns_random(50000));
    
    if(::bind(d_sock, (struct sockaddr *)&local, local.getSocklen()) >= 0) 
      break;
  }
  if(n==10) {
    closesocket(d_sock);
    d_sock=-1;
    throw PDNSException(string("binding dnsproxy socket: ")+stringerror());
  }

  if(connect(d_sock, (sockaddr *)&d_remote, d_remote.getSocklen())<0) {
    throw PDNSException("Unable to UDP connect to remote nameserver "+d_remote.toStringWithPort()+": "+stringerror());
  }

  d_xor=dns_random_uint16();
  g_log<<Logger::Error<<"DNS Proxy launched, local port "<<ntohs(local.sin4.sin_port)<<", remote "<<d_remote.toStringWithPort()<<endl;
} 

void DNSProxy::go()
{
  pthread_t tid;
  pthread_create(&tid,0,&launchhelper,this);
}

//! look up qname target with r->qtype, plonk it in the answer section of 'r' with name aname
bool DNSProxy::completePacket(std::unique_ptr<DNSPacket>& r, const DNSName& target,const DNSName& aname, const uint8_t scopeMask)
{
  if(r->d_tcp) {
    vector<DNSZoneRecord> ips;
    int ret1 = 0, ret2 = 0;

    if(r->qtype == QType::A || r->qtype == QType::ANY)
      ret1 = stubDoResolve(target, QType::A, ips);
    if(r->qtype == QType::AAAA || r->qtype == QType::ANY)
      ret2 = stubDoResolve(target, QType::AAAA, ips);

    if(ret1 != RCode::NoError || ret2 != RCode::NoError) {
      g_log<<Logger::Error<<"Error resolving for "<<aname<<" ALIAS "<<target<<" over UDP, original query came in over TCP";
      if (ret1 != RCode::NoError) {
       g_log<<Logger::Error<<", A-record query returned "<<RCode::to_s(ret1);
      }
      if (ret2 != RCode::NoError) {
       g_log<<Logger::Error<<", AAAA-record query returned "<<RCode::to_s(ret2);
      }
      g_log<<Logger::Error<<", returning SERVFAIL"<<endl;
      r->clearRecords();
      r->setRcode(RCode::ServFail);
    } else {
      for (auto &ip : ips)
      {
        ip.dr.d_name = aname;
        r->addRecord(ip);
      }
    }

    uint16_t len=htons(r->getString().length());
    string buffer((const char*)&len, 2);
    buffer.append(r->getString());
    writen2WithTimeout(r->getSocket(), buffer.c_str(), buffer.length(), ::arg().asNum("tcp-idle-timeout"));

    return true;
  }

  uint16_t id;
  uint16_t qtype = r->qtype.getCode();
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
    ce.complete = std::move(r);
    ce.aname=aname;
    ce.anameScopeMask = scopeMask;
    d_conntrack[id]=std::move(ce);
  }

  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, target, qtype);
  pw.getHeader()->rd=true;
  pw.getHeader()->id=id ^ d_xor;

  if(send(d_sock,&packet[0], packet.size() , 0)<0) { // zoom
    g_log<<Logger::Error<<"Unable to send a packet to our recursing backend: "<<stringerror()<<endl;
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
        g_log<<Logger::Warning<<"Recursive query for remote "<<
          i->second.remote.toStringWithPort()<<" with internal id "<<n<<
          " was not answered by backend within timeout, reusing id"<<endl;
	i->second.complete.reset();
	S.inc("recursion-unanswered");
      }
      return n;
    }
  }
}

void DNSProxy::mainloop(void)
{
  setThreadName("pdns/dnsproxy");
  try {
    char buffer[1500];
    ssize_t len;

    struct msghdr msgh;
    struct iovec iov;
    cmsgbuf_aligned cbuf;
    ComboAddress fromaddr;

    for(;;) {
      socklen_t fromaddrSize = sizeof(fromaddr);
      len=recvfrom(d_sock, buffer, sizeof(buffer),0, (struct sockaddr*) &fromaddr, &fromaddrSize); // answer from our backend
      if(len<(ssize_t)sizeof(dnsheader)) {
        if(len<0)
          g_log<<Logger::Error<<"Error receiving packet from recursor backend: "<<stringerror()<<endl;
        else if(len==0)
          g_log<<Logger::Error<<"Error receiving packet from recursor backend, EOF"<<endl;
        else
          g_log<<Logger::Error<<"Short packet from recursor backend, "<<len<<" bytes"<<endl;
        
        continue;
      }
      if (fromaddr != d_remote) {
        g_log<<Logger::Error<<"Got answer from unexpected host "<<fromaddr.toStringWithPort()<<" instead of our recursor backend "<<d_remote.toStringWithPort()<<endl;
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
          g_log<<Logger::Error<<"Discarding untracked packet from recursor backend with id "<<(d.id^d_xor)<<
            ". Conntrack table size="<<d_conntrack.size()<<endl;
          continue;
        }
        else if(i->second.created==0) {
          g_log<<Logger::Error<<"Received packet from recursor backend with id "<<(d.id^d_xor)<<" which is a duplicate"<<endl;
          continue;
        }
	
        d.id=i->second.id;
        memcpy(buffer,&d,sizeof(d));  // commit spoofed id

        DNSPacket p(false),q(false);
        p.parse(buffer,(size_t)len);
        q.parse(buffer,(size_t)len);

        if(p.qtype.getCode() != i->second.qtype || p.qdomain != i->second.qname) {
          g_log<<Logger::Error<<"Discarding packet from recursor backend with id "<<(d.id^d_xor)<<
            ", qname or qtype mismatch ("<<p.qtype.getCode()<<" v " <<i->second.qtype<<", "<<p.qdomain<<" v "<<i->second.qname<<")"<<endl;
          continue;
        }

        /* Set up iov and msgh structures. */
        memset(&msgh, 0, sizeof(struct msghdr));
        string reply; // needs to be alive at time of sendmsg!
        MOADNSParser mdp(false, p.getString());
        //	  cerr<<"Got completion, "<<mdp.d_answers.size()<<" answers, rcode: "<<mdp.d_header.rcode<<endl;
        if (mdp.d_header.rcode == RCode::NoError) {
          for(MOADNSParser::answers_t::const_iterator j=mdp.d_answers.begin(); j!=mdp.d_answers.end(); ++j) {        
            //	    cerr<<"comp: "<<(int)j->first.d_place-1<<" "<<j->first.d_label<<" " << DNSRecordContent::NumberToType(j->first.d_type)<<" "<<j->first.d_content->getZoneRepresentation()<<endl;
            if(j->first.d_place == DNSResourceRecord::ANSWER || (j->first.d_place == DNSResourceRecord::AUTHORITY && j->first.d_type == QType::SOA)) {

              if(j->first.d_type == i->second.qtype || (i->second.qtype == QType::ANY && (j->first.d_type == QType::A || j->first.d_type == QType::AAAA))) {
                DNSZoneRecord dzr;
                dzr.dr.d_name=i->second.aname;
                dzr.dr.d_type = j->first.d_type;
                dzr.dr.d_ttl=j->first.d_ttl;
                dzr.dr.d_place= j->first.d_place;
                dzr.dr.d_content=j->first.d_content;
                i->second.complete->addRecord(dzr);
              }
            }
          }
          i->second.complete->setRcode(mdp.d_header.rcode);
        } else {
          g_log<<Logger::Error<<"Error resolving for "<<i->second.aname<<" ALIAS "<<i->second.qname<<" over UDP, "<<QType(i->second.qtype).getName()<<"-record query returned "<<RCode::to_s(mdp.d_header.rcode)<<", returning SERVFAIL"<<endl;
          i->second.complete->clearRecords();
          i->second.complete->setRcode(RCode::ServFail);
        }
        reply=i->second.complete->getString();
        iov.iov_base = (void*)reply.c_str();
        iov.iov_len = reply.length();
        i->second.complete.reset();
        msgh.msg_iov = &iov;
        msgh.msg_iovlen = 1;
        msgh.msg_name = (struct sockaddr*)&i->second.remote;
        msgh.msg_namelen = i->second.remote.getSocklen();
        msgh.msg_control=NULL;

        if(i->second.anyLocal) {
          addCMsgSrcAddr(&msgh, &cbuf, i->second.anyLocal.get_ptr(), 0);
        }
        if(sendmsg(i->second.outsock, &msgh, 0) < 0) {
          int err = errno;
          g_log<<Logger::Warning<<"dnsproxy.cc: Error sending reply with sendmsg (socket="<<i->second.outsock<<"): "<<stringerror(err)<<endl;
        }
        i->second.created=0;
      }
    }
  }
  catch(PDNSException &ae) {
    g_log<<Logger::Error<<"Fatal error in DNS proxy: "<<ae.reason<<endl;
  }
  catch(std::exception &e) {
    g_log<<Logger::Error<<"Communicator thread died because of STL error: "<<e.what()<<endl;
  }
  catch( ... )
  {
    g_log << Logger::Error << "Caught unknown exception." << endl;
  }
  g_log<<Logger::Error<<"Exiting because DNS proxy failed"<<endl;
  _exit(1);
}

DNSProxy::~DNSProxy() {
  if (d_sock>-1) {
    try {
      closesocket(d_sock);
    }
    catch(const PDNSException& e) {
    }
  }

  d_sock=-1;
}
