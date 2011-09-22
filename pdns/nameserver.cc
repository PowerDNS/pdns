/*
    Copyright (C) 2002 - 2007  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "utility.hh"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <iostream>
#include <string>
#include <sys/types.h>
#include <boost/shared_ptr.hpp>
#include "dns.hh"
#include "dnsbackend.hh"
#include "dnspacket.hh"
#include "nameserver.hh"
#include "distributor.hh"
#include "logger.hh"
#include "arguments.hh"
#include "statbag.hh"

#include "namespaces.hh"

extern StatBag S;

/** \mainpage 
    PowerDNS is a very versatile nameserver that can answer questions from different backends. To implement your
    own backend, see the documentation for the DNSBackend class.

    \section copyright Copyright and License
    PowerDNS is (C) 2001-2008 PowerDNS.COM BV. It is distributed according to the terms of the General Public License version 2.

    \section overview High level overview

    The Distributor contains a configurable number of PacketHandler instances, each in its own thread, for connection pooling. 
    PacketHandler instances are recycled of they let escape an AhuException.

    The PacketHandler implements the RFC1034 algorithm and converts question packets into DNSBackend queries.

    A DNSBackend is an entity that returns DNSResourceRecord objects in return to explicit questions for domains with a specified QType

    PowerDNS uses the UeberBackend as its DNSBackend. The UeberBackend by default has no DNSBackends within itself, those are loaded
    using the pdns_control tool. This way DNSBackend implementations can be kept completely separate (but they often aren't).s

    If one or more DNSBackends are loaded, the UeberBackend fields the queries to all of them until one answers.

    \section TCP TCP Operations

    The TCP operation runs within a single thread called tcpreceiver(), that also queries the PacketHandler. 

    \section Cache Caching
 
    On its own, this setup is not suitable for high performance operations. A single DNS query can turn into many DNSBackend questions,
    each taking many miliseconds to complete. This is why the qthread() first checks the PacketCache to see if an answer is known to a packet
    asking this question. If so, the entire Distributor is shunted, and the answer is sent back *directly*, within a few microseconds.

    \section misc Miscellaneous
    Configuration details are available via the ArgvMap instance arg. Statistics are created by making calls to the StatBag object called S. 
    These statistics are made available via the UeberBackend on the same socket that is used for dynamic module commands.

    \section Main Main 
    The main() of PowerDNS can be found in receiver.cc - start reading there for further insights into the operation of the nameserver
*/

void UDPNameserver::bindIPv4()
{
  vector<string>locals;
  stringtok(locals,::arg()["local-address"]," ,");

  if(locals.empty())
    throw AhuException("No local address specified");

  int s;
  for(vector<string>::const_iterator i=locals.begin();i!=locals.end();++i) {
    string localname(*i);
    struct sockaddr_in locala;

    s=socket(AF_INET,SOCK_DGRAM,0);
    Utility::setCloseOnExec(s);

    if(s<0)
      throw AhuException("Unable to acquire a UDP socket: "+string(strerror(errno)));
  
    if(locals.size() > 1 && !Utility::setNonBlocking(s))
      throw AhuException("Unable to set UDP socket to non-blocking: "+stringerror());
  
    memset(&locala,0,sizeof(locala));
    locala.sin_family=AF_INET;

    if(localname=="0.0.0.0") {
      L<<Logger::Warning<<"It is advised to bind to explicit addresses with the --local-address option"<<endl;

      locala.sin_addr.s_addr = INADDR_ANY;
    }
    else
    {
      struct hostent *h=0;
      h=gethostbyname(localname.c_str());
      if(!h)
        throw AhuException("Unable to resolve local address"); 

      locala.sin_addr.s_addr=*(int*)h->h_addr;
    }

    locala.sin_port=htons(::arg().asNum("local-port"));
    
    if(::bind(s, (sockaddr*)&locala,sizeof(locala))<0) {
      L<<Logger::Error<<"binding UDP socket to '"+localname+"' port "+lexical_cast<string>(ntohs(locala.sin_port))+": "<<strerror(errno)<<endl;
      throw AhuException("Unable to bind to UDP socket");
    }
    d_highfd=max(s,d_highfd);
    d_sockets.push_back(s);
    L<<Logger::Error<<"UDP server bound to "<<inet_ntoa(locala.sin_addr)<<":"<<::arg().asNum("local-port")<<endl;
    FD_SET(s, &d_rfds);
  }
}

void UDPNameserver::bindIPv6()
{
#if !WIN32 && HAVE_IPV6
  vector<string>locals;
  stringtok(locals,::arg()["local-ipv6"]," ,");

  if(locals.empty())
    return;

  int s;
  for(vector<string>::const_iterator i=locals.begin();i!=locals.end();++i) {
    string localname(*i);

    s=socket(AF_INET6,SOCK_DGRAM,0);
    Utility::setCloseOnExec(s);
    if(s<0)
      throw AhuException("Unable to acquire a UDPv6 socket: "+string(strerror(errno)));
  
    if(localname=="::0") {
      L<<Logger::Warning<<"It is advised to bind to explicit addresses with the --local-ipv6 option"<<endl;
    }
    
    ComboAddress locala(localname, ::arg().asNum("local-port"));

    if(::bind(s, (sockaddr*)&locala, sizeof(locala))<0) {
      L<<Logger::Error<<"binding to UDP ipv6 socket: "<<strerror(errno)<<endl;
      throw AhuException("Unable to bind to UDP ipv6 socket");
    }
    d_highfd=max(s,d_highfd);
    d_sockets.push_back(s);
    L<<Logger::Error<<"UDPv6 server bound to "<<locala.toStringWithPort()<<endl;
    FD_SET(s, &d_rfds);
  }
#endif // WIN32
}

UDPNameserver::UDPNameserver()
{
  d_highfd=0;
  FD_ZERO(&d_rfds);  
  if(!::arg()["local-address"].empty())
    bindIPv4();
  if(!::arg()["local-ipv6"].empty())
    bindIPv6();

  if(::arg()["local-address"].empty() && ::arg()["local-ipv6"].empty()) 
    L<<Logger::Critical<<"PDNS is deaf and mute! Not listening on any interfaces"<<endl;
    
}

void UDPNameserver::send(DNSPacket *p)
{
  const string& buffer=p->getString();
  DLOG(L<<Logger::Notice<<"Sending a packet to "<< p->getRemote() <<" ("<< buffer.length()<<" octets)"<<endl);
  if(buffer.length() > p->getMaxReplyLen()) {
    cerr<<"Weird, trying to send a message that needs truncation, "<< buffer.length()<<" > "<<p->getMaxReplyLen()<<endl;
  }
  if(sendto(p->getSocket(),buffer.c_str(), buffer.length(), 0, (struct sockaddr *)(&p->d_remote), p->d_remote.getSocklen()) < 0)
    L<<Logger::Error<<"Error sending reply with sendto (socket="<<p->getSocket()<<"): "<<strerror(errno)<<endl;
}

