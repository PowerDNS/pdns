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
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include "utility.hh"
#include "lwres.hh"
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
#include "logger.hh"

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


//! returns -2 for OS limits error, -1 for permanent error that has to do with remote, 0 for timeout, 1 for success
/** Never throws! */
int LWRes::asyncresolve(const ComboAddress& ip, const string& domain, int type, bool doTCP, struct timeval* now)
{
  d_ip=ip;
  vector<uint8_t> vpacket;
  DNSPacketWriter pw(vpacket, domain, type);

  pw.getHeader()->rd=0;
  pw.getHeader()->id=Utility::random();
  d_domain=domain;
  d_type=type;
  d_inaxfr=false;
  d_rcode=0;

  int ret;

  DTime dt;
  dt.setTimeval(*now);

  if(!doTCP) {
    int queryfd;
    if(ip.sin4.sin_family==AF_INET6)
      g_stats.ipv6queries++;

    if((ret=asendto((const char*)&*vpacket.begin(), vpacket.size(), 0, ip, pw.getHeader()->id, domain, &queryfd)) < 0) {
      return ret; // passes back the -2 EMFILE
    }
  
    // sleep until we see an answer to this, interface to mtasker
    
    ret=arecvfrom(reinterpret_cast<char *>(d_buf), d_bufsize-1,0, ip, &d_len, pw.getHeader()->id, domain, queryfd);
  }
  else {
    try {
      if(ip.sin4.sin_addr.s_addr != AF_INET) // sstuff isn't yet ready for IPv6
	return -1;

      Socket s(InterNetwork, Stream);
      IPEndpoint ie(U32ToIP(ip.sin4.sin_addr.s_addr), 53);   // WRONG WRONG WRONG XXX FIXME
      s.setNonBlocking();
      s.connect(ie);
      
      unsigned int len=htons(vpacket.size());
      char *lenP=(char*)&len;
      const char *msgP=(const char*)&*vpacket.begin();
      string packet=string(lenP, lenP+2)+string(msgP, msgP+vpacket.size());
      
      ret=asendtcp(packet, &s);
      if(!(ret>0))           
	return ret;
      
      packet.clear();
      ret=arecvtcp(packet, 2, &s);
      if(!(ret > 0))
	return ret;
      
      memcpy(&len, packet.c_str(), 2);
      len=ntohs(len);
      
      ret=arecvtcp(packet, len, &s);
      if(!(ret > 0))
	return ret;
      
      if(len > (unsigned int)d_bufsize) {
	d_bufsize=len;
	delete[] d_buf;
	d_buf = new unsigned char[d_bufsize];
      }
      memcpy(d_buf, packet.c_str(), len);
      d_len=len;
      ret=1;
    }
    catch(NetworkError& ne) {
      ret = -2; // OS limits error
    }
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

    if(strcasecmp(d_domain.c_str(), mdp.d_qname.c_str())) { 
      if(d_domain.find((char)0)==string::npos) {// embedded nulls are too noisy
	L<<Logger::Error<<"Packet purporting to come from remote server "<<d_ip.toString()<<" contained wrong answer: '" << d_domain << "' != '" << mdp.d_qname << "'" << endl;
	g_stats.unexpectedCount++;
      }
      goto out;
    }

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
  catch(exception &mde) {
    if(::arg().mustDo("log-common-errors"))
      L<<Logger::Error<<"Unable to parse packet from remote server: "<<mde.what()<<endl;
  }
  catch(...) {
    L<<Logger::Error<<"Unknown error parsing packet from remote server"<<endl;
  }

  g_stats.serverParseError++; 

 out:
  d_rcode=RCode::ServFail;
  LWRes::res_t empty;
  return empty;
}

