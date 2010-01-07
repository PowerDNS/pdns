/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2010 PowerDNS.COM BV

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
#include "dnsrecords.hh"
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
#include "dns_random.hh"
#include <boost/scoped_array.hpp>
#include <boost/algorithm/string.hpp>

string dns0x20(const std::string& in)
{
  string ret(in);
  string::size_type len=ret.size();
  for(string::size_type pos = 0 ; pos < len; ++pos) {
    if(isalpha(in[pos]) && dns_random(2))
      ret[pos]^=0x20;
  }
  //  cerr<<"'"<<in<<"' -> '"<<ret<<"'\n";
  return ret;
}

//! returns -2 for OS limits error, -1 for permanent error that has to do with remote **transport**, 0 for timeout, 1 for success
/** lwr is only filled out in case 1 was returned, and even when returning 1 for 'success', lwr might contain DNS errors
    Never throws! 
 */
int asyncresolve(const ComboAddress& ip, const string& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, LWResult *lwr)
{
  int len; 
  int bufsize=1500;
  scoped_array<unsigned char> buf(new unsigned char[bufsize]);
  vector<uint8_t> vpacket;
  //  string mapped0x20=dns0x20(domain);
  DNSPacketWriter pw(vpacket, domain, type);

  pw.getHeader()->rd=sendRDQuery;
  pw.getHeader()->id=dns_random(0xffff);
  
  string ping;

  uint32_t nonce=dns_random(0xffffffff);
  ping.assign((char*) &nonce, 4);

  if(EDNS0Level && !doTCP) {
    DNSPacketWriter::optvect_t opts;
    if(EDNS0Level > 1) {
      opts.push_back(make_pair(5, ping));
    }

    pw.addOpt(1200, 0, 0, opts); // 1200 bytes answer size
    pw.commit();
  }
  lwr->d_rcode = 0;
  lwr->d_pingCorrect = false;
  lwr->d_haveEDNS = false;

  int ret;

  DTime dt;
  dt.setTimeval(*now);
  errno=0;
  if(!doTCP) {
    int queryfd;
    if(ip.sin4.sin_family==AF_INET6)
      g_stats.ipv6queries++;

    if((ret=asendto((const char*)&*vpacket.begin(), (int)vpacket.size(), 0, ip, pw.getHeader()->id, 
        	    domain, type, &queryfd)) < 0) {
      return ret; // passes back the -2 EMFILE
    }
  
    // sleep until we see an answer to this, interface to mtasker
    
    ret=arecvfrom(reinterpret_cast<char *>(buf.get()), bufsize-1,0, ip, &len, pw.getHeader()->id, 
        	  domain, type, queryfd, now);
  }
  else {
    try {
      Socket s((AddressFamily)ip.sin4.sin_family, Stream);

      s.setNonBlocking();
      ComboAddress local = getQueryLocalAddress(ip.sin4.sin_family, 0);

      s.bind(local);
        
      ComboAddress remote = ip;
      remote.sin4.sin_port = htons(53);      
      s.connect(remote);
      
      uint16_t tlen=htons(vpacket.size());
      char *lenP=(char*)&tlen;
      const char *msgP=(const char*)&*vpacket.begin();
      string packet=string(lenP, lenP+2)+string(msgP, msgP+vpacket.size());
      
      ret=asendtcp(packet, &s);
      if(!(ret>0))           
        return ret;
      
      packet.clear();
      ret=arecvtcp(packet, 2, &s);
      if(!(ret > 0))
        return ret;
      
      memcpy(&tlen, packet.c_str(), 2);
      len=ntohs(tlen); // switch to the 'len' shared with the rest of the function
      
      ret=arecvtcp(packet, len, &s);
      if(!(ret > 0))
        return ret;
      
      if(len > bufsize) {
        bufsize=len;
        scoped_array<unsigned char> narray(new unsigned char[bufsize]);
        buf.swap(narray);
      }
      memcpy(buf.get(), packet.c_str(), len);

      ret=1;
    }
    catch(NetworkError& ne) {
      ret = -2; // OS limits error
    }
  }

  
  lwr->d_usec=dt.udiff();
  *now=dt.getTimeval();

  if(ret <= 0) // includes 'timeout'
    return ret;

  lwr->d_result.clear();
  try {
    MOADNSParser mdp((const char*)buf.get(), len);
    lwr->d_aabit=mdp.d_header.aa;
    lwr->d_tcbit=mdp.d_header.tc;
    lwr->d_rcode=mdp.d_header.rcode;
    
    if(mdp.d_header.rcode == RCode::FormErr && mdp.d_qname.empty() && mdp.d_qtype == 0 && mdp.d_qclass == 0) {
      return 1; // this is "success", the error is set in lwr->d_rcode
    }

    if(!pdns_iequals(domain, mdp.d_qname)) { 
      if(!mdp.d_qname.empty() && domain.find((char)0) == string::npos) {// embedded nulls are too noisy, plus empty domains are too
        L<<Logger::Notice<<"Packet purporting to come from remote server "<<ip.toString()<<" contained wrong answer: '" << domain << "' != '" << mdp.d_qname << "'" << endl;
      }
      g_stats.unexpectedCount++;
      goto out;
    }

    for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {          
      DNSResourceRecord rr;
      rr.priority = 0;
      rr.qtype=i->first.d_type;
      rr.qname=i->first.d_label;
    
      rr.ttl=i->first.d_ttl;
      rr.content=i->first.d_content->getZoneRepresentation();  // this should be the serialised form
      rr.d_place=(DNSResourceRecord::Place) i->first.d_place;
      lwr->d_result.push_back(rr);
    }

    EDNSOpts edo;
    if(EDNS0Level > 1 && getEDNSOpts(mdp, &edo)) {
      lwr->d_haveEDNS = true;
      for(vector<pair<uint16_t, string> >::const_iterator iter = edo.d_options.begin();
          iter != edo.d_options.end(); 
          ++iter) {
        if(iter->first == 5 || iter->first == 4) {// 'EDNS PING'
          if(iter->second == ping)  {
            lwr->d_pingCorrect = true;
          }
        }
      }
    }
        
    return 1;
  }
  catch(std::exception &mde) {
    if(::arg().mustDo("log-common-errors"))
      L<<Logger::Notice<<"Unable to parse packet from remote server "<<ip.toString()<<": "<<mde.what()<<endl;
    lwr->d_rcode = RCode::FormErr;
    g_stats.serverParseError++; 
    return 1; // success - oddly enough
  }
  catch(...) {
    L<<Logger::Notice<<"Unknown error parsing packet from remote server"<<endl;
  }
  
  g_stats.serverParseError++; 
  
 out:
  if(!lwr->d_rcode)
    lwr->d_rcode=RCode::ServFail;

  return -1;
}


