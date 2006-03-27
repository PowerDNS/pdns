/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2005 PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
#include "utility.hh"
#include "lwres.hh"
#include <pthread.h>
#include <semaphore.h>
#include <iostream>
#include <errno.h>
#include "misc.hh"
#include <algorithm>
#include <sstream>
#include <cstring>
#include <string>
#include <vector>
#include "dns.hh"
#include "qtype.hh"
#include "ahuexception.hh"
#include "arguments.hh"
#include "sstuff.hh"
#include "syncres.hh"
#include "dnswriter.hh"
#include "dnsparser.hh"

LWRes::LWRes()
{
  d_sock=-1;
  d_timeout=500000;
  d_bufsize=1500;
  d_buf=new unsigned char[d_bufsize];
}

LWRes::~LWRes()
{
  if(d_sock>=0)
    Utility::closesocket(d_sock);
  delete[] d_buf;
}


//! returns -1 for permanent error, 0 for timeout, 1 for success
/** Never throws! */
int LWRes::asyncresolve(uint32_t ip, const char *domain, int type, bool doTCP, struct timeval* now)
{
  vector<uint8_t> vpacket;
  DNSPacketWriter pw(vpacket, domain, type);

  pw.getHeader()->rd=0;
  pw.getHeader()->id=random();
  d_domain=domain;
  d_type=type;
  d_inaxfr=false;
  d_rcode=0;

  struct sockaddr_in toaddr;
  Utility::socklen_t addrlen=sizeof(toaddr);
  toaddr.sin_addr.s_addr=htonl(ip);

  toaddr.sin_port=htons(53);
  toaddr.sin_family=AF_INET;

  int ret;

  DTime dt;
  dt.setTimeval(*now);

  if(!doTCP) {
    if(asendto((const char*)&*vpacket.begin(), vpacket.size(), 0, (struct sockaddr*)(&toaddr), sizeof(toaddr), pw.getHeader()->id)<0) {
      return -1;
    }
  
    // sleep until we see an answer to this, interface to mtasker
    
    ret=arecvfrom(reinterpret_cast<char *>(d_buf), d_bufsize-1,0,(struct sockaddr*)(&toaddr), &addrlen, &d_len, pw.getHeader()->id);
  }
  else {
    Socket s(InterNetwork, Stream);
    IPEndpoint ie(U32ToIP(ip), 53);
    s.setNonBlocking();
    s.connect(ie);

    unsigned int len=htons(vpacket.size());
    char *lenP=(char*)&len;
    const char *msgP=(const char*)&*vpacket.begin();
    string packet=string(lenP, lenP+2)+string(msgP, msgP+vpacket.size());

    if(asendtcp(packet, &s) == 0) {
      //      cerr<<"asendtcp: timeout"<<endl;
      return 0;
    }
    
    packet.clear();
    if(arecvtcp(packet,2, &s)==0) {
      //      cerr<<"arecvtcp: timeout"<<endl;
      return 0;
    }

    memcpy(&len, packet.c_str(), 2);
    len=ntohs(len);

    //    cerr<<"Now reading "<<len<<" bytes"<<endl;

    if(arecvtcp(packet, len, &s)==0) {
      //      cerr<<"arecvtcp: timeout"<<endl;
      return 0;
    }
    if(len > (unsigned int)d_bufsize) {
      d_bufsize=len;
      delete[] d_buf;
      d_buf = new unsigned char[d_bufsize];
    }
    memcpy(d_buf, packet.c_str(), len);
    d_len=len;
    ret=1;
  }
  d_usec=dt.udiff();
  *now=dt.getTimeval();
  return ret;
}


LWRes::res_t LWRes::result()
{
  try {
    MOADNSParser mdp((const char*)d_buf, d_len);
    //    if(p.parse((char *)d_buf, d_len)<0)
    //      throw LWResException("resolver: unable to parse packet of "+itoa(d_len)+" bytes");
    d_aabit=mdp.d_header.aa;
    d_tcbit=mdp.d_header.tc;
    d_rcode=mdp.d_header.rcode;

    LWRes::res_t ret;
    for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {          
      //      cout<<i->first.d_place<<"\t"<<i->first.d_label<<"\tIN\t"<<DNSRecordContent::NumberToType(i->first.d_type);
      //      cout<<"\t"<<i->first.d_ttl<<"\t"<< i->first.d_content->getZoneRepresentation()<<endl;
      DNSResourceRecord rr;
      rr.qtype=i->first.d_type;
      rr.qname=i->first.d_label;
      rr.ttl=i->first.d_ttl;
      rr.content=i->first.d_content->getZoneRepresentation();  // this should be the serialised form
      
      rr.d_place=(DNSResourceRecord::Place) i->first.d_place;
      ret.push_back(rr);
    }

    return ret;
    //    return p.getAnswers();
  }
  catch(...) {
    d_rcode=RCode::ServFail;
    LWRes::res_t empty;
    return empty;
  }
}

