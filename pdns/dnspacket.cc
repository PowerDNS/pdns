/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2001 - 2010  PowerDNS.COM BV

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
#include <cstdio>

#include <cstdlib>
#include <sys/types.h>

#include <iostream>  

#include <string>
#include <errno.h>
#include <boost/tokenizer.hpp>
#include <boost/algorithm/string.hpp>
#include <polarssl/havege.h>
#include <algorithm>
#include <boost/foreach.hpp>
#include "dnsseckeeper.hh"
#include "dns.hh"
#include "dnsbackend.hh"
#include "ahuexception.hh"
#include "dnspacket.hh"
#include "logger.hh"
#include "arguments.hh"
#include "dnswriter.hh"
#include "dnsparser.hh"
#include "dnsrecords.hh"
#include <polarssl/rsa.h> 
#include "dnssecinfra.hh" 

DNSPacket::DNSPacket() 
{
  d_wrapped=false;
  d_compress=true;
  d_tcp=false;
  d_wantsnsid=false;
  d_dnssecOk=false;
}

string DNSPacket::getString()
{
  return stringbuffer;
}

const char *DNSPacket::getData(void)
{
  if(!d_wrapped)
    wrapup();

  return stringbuffer.data();
}

const char *DNSPacket::getRaw(void)
{
  return stringbuffer.data();
}

string DNSPacket::getRemote() const
{
  return remote.toString();
}

uint16_t DNSPacket::getRemotePort() const
{
  return remote.sin4.sin_port;
}

DNSPacket::DNSPacket(const DNSPacket &orig)
{
  DLOG(L<<"DNSPacket copy constructor called!"<<endl);
  d_socket=orig.d_socket;
  remote=orig.remote;
  len=orig.len;
  d_qlen=orig.d_qlen;
  d_dt=orig.d_dt;
  d_compress=orig.d_compress;
  d_tcp=orig.d_tcp;
  qtype=orig.qtype;
  qclass=orig.qclass;
  qdomain=orig.qdomain;
  d_maxreplylen = orig.d_maxreplylen;
  d_ednsping = orig.d_ednsping;
  d_wantsnsid = orig.d_wantsnsid;
  d_dnssecOk = orig.d_dnssecOk;
  d_rrs=orig.d_rrs;

  d_wrapped=orig.d_wrapped;

  stringbuffer=orig.stringbuffer;
  d=orig.d;
}

void DNSPacket::setRcode(int v)
{
  d.rcode=v;
}

void DNSPacket::setAnswer(bool b)
{
  if(b) {
    stringbuffer.assign(12,(char)0);
    memset((void *)&d,0,sizeof(d));
    
    d.qr=b;
  }
}

void DNSPacket::setA(bool b)
{
  d.aa=b;
}

void DNSPacket::setID(uint16_t id)
{
  d.id=id;
}

void DNSPacket::setRA(bool b)
{
  d.ra=b;
}

void DNSPacket::setRD(bool b)
{
  d.rd=b;
}

void DNSPacket::setOpcode(uint16_t opcode)
{
  d.opcode=opcode;
}


void DNSPacket::clearRecords()
{
  d_rrs.clear();
}

void DNSPacket::addRecord(const DNSResourceRecord &rr)
{
  if(d_compress)
    for(vector<DNSResourceRecord>::const_iterator i=d_rrs.begin();i!=d_rrs.end();++i) 
      if(rr.qname==i->qname && rr.qtype==i->qtype && rr.content==i->content) {
        if(rr.qtype.getCode()!=QType::MX && rr.qtype.getCode()!=QType::SRV)
          return;
        if(rr.priority==i->priority)
          return;
      }

  d_rrs.push_back(rr);
}

// the functions below update the 'arcount' and 'ancount', plus they serialize themselves to the stringbuffer

string& attodot(string &str)
{
   if(str.find_first_of("@")==string::npos)
      return str;

   for (unsigned int i = 0; i < str.length(); i++)
   {
      if (str[i] == '@') {
         str[i] = '.';
         break;
      } else if (str[i] == '.') {
         str.insert(i++, "\\");
      }
   }

   return str;
}

void fillSOAData(const string &content, SOAData &data)
{
  // content consists of fields separated by spaces:
  //  nameservername hostmaster serial-number [refresh [retry [expire [ minimum] ] ] ]

  // fill out data with some plausible defaults:
  // 10800 3600 604800 3600
  data.serial=0;
  data.refresh=::arg().asNum("soa-refresh-default");
  data.retry=::arg().asNum("soa-retry-default");
  data.expire=::arg().asNum("soa-expire-default");
  data.default_ttl=::arg().asNum("soa-minimum-ttl");

  vector<string>parts;
  stringtok(parts,content);
  int pleft=parts.size();

  //  cout<<"'"<<content<<"'"<<endl;

  if(pleft)
    data.nameserver=parts[0];

  if(pleft>1) 
    data.hostmaster=attodot(parts[1]); // ahu@ds9a.nl -> ahu.ds9a.nl, piet.puk@ds9a.nl -> piet\.puk.ds9a.nl

  if(pleft>2)
    data.serial=strtoul(parts[2].c_str(), NULL, 10);

  if(pleft>3)
    data.refresh=atoi(parts[3].c_str());

  if(pleft>4)
    data.retry=atoi(parts[4].c_str());

  if(pleft>5)
    data.expire=atoi(parts[5].c_str());

  if(pleft>6)
    data.default_ttl=atoi(parts[6].c_str());

}

string serializeSOAData(const SOAData &d)
{
  ostringstream o;
  //  nameservername hostmaster serial-number [refresh [retry [expire [ minimum] ] ] ]
  o<<d.nameserver<<" "<< d.hostmaster <<" "<< d.serial <<" "<< d.refresh << " "<< d.retry << " "<< d.expire << " "<< d.default_ttl;

  return o.str();
}


static int rrcomp(const DNSResourceRecord &A, const DNSResourceRecord &B)
{
  if(A.d_place<B.d_place)
    return 1;

  return 0;
}

vector<DNSResourceRecord*> DNSPacket::getAPRecords()
{
  vector<DNSResourceRecord*> arrs;

  for(vector<DNSResourceRecord>::iterator i=d_rrs.begin();
      i!=d_rrs.end();
      ++i)
    {
      if(i->d_place!=DNSResourceRecord::ADDITIONAL && 
         (i->qtype.getCode()==15 || 
          i->qtype.getCode()==2 )) // CNAME or MX or NS
        {
          arrs.push_back(&*i);
        }
    }

  return arrs;

}

vector<DNSResourceRecord*> DNSPacket::getAnswerRecords()
{
  vector<DNSResourceRecord*> arrs;

  for(vector<DNSResourceRecord>::iterator i=d_rrs.begin();
      i!=d_rrs.end();
      ++i)
    {
      if(i->d_place!=DNSResourceRecord::ADDITIONAL) 
	arrs.push_back(&*i);
    }
  return arrs;
}


void DNSPacket::setCompress(bool compress)
{
  d_compress=compress;
  stringbuffer.reserve(65000);
  d_rrs.reserve(200);
}

bool DNSPacket::couldBeCached()
{
  return d_ednsping.empty() && !d_wantsnsid && qclass==QClass::IN;
}

/** Must be called before attempting to access getData(). This function stuffs all resource
 *  records found in rrs into the data buffer. It also frees resource records queued for us.
 */
void DNSPacket::wrapup(void)
{
  if(d_wrapped) {
    return;
  }
  
  // do embedded-additional processing decapsulation
  DNSResourceRecord rr;
  vector<DNSResourceRecord>::iterator pos;

  vector<DNSResourceRecord> additional;

  int ipos=d_rrs.size();
  d_rrs.resize(d_rrs.size()+additional.size());
  copy(additional.begin(), additional.end(), d_rrs.begin()+ipos);

  // we now need to order rrs so that the different sections come at the right place
  // we want a stable sort, based on the d_place field

  stable_sort(d_rrs.begin(),d_rrs.end(),rrcomp);

  static bool mustShuffle =::arg().mustDo("no-shuffle");

  if(!d_tcp && !mustShuffle) {
    shuffle(d_rrs);
  }
  d_wrapped=true;

  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, qdomain, qtype.getCode(), qclass);

  pw.getHeader()->rcode=d.rcode;
  pw.getHeader()->aa=d.aa;
  pw.getHeader()->ra=d.ra;
  pw.getHeader()->qr=d.qr;
  pw.getHeader()->id=d.id;
  pw.getHeader()->rd=d.rd;

  DNSPacketWriter::optvect_t opts;
  if(d_wantsnsid) {
    opts.push_back(make_pair(3, ::arg()["server-id"]));
  }

  if(!d_ednsping.empty()) {
    opts.push_back(make_pair(4, d_ednsping));
  }

  if(!d_rrs.empty() || !opts.empty()) {
    try {
      string signQName, wildcardQName;
      uint16_t signQType=0;
      uint32_t signTTL=0;
      DNSPacketWriter::Place signPlace=DNSPacketWriter::ANSWER;
      vector<shared_ptr<DNSRecordContent> > toSign;

      for(pos=d_rrs.begin(); pos < d_rrs.end(); ++pos) {
        // this needs to deal with the 'prio' mismatch!
        if(pos->qtype.getCode()==QType::MX || pos->qtype.getCode() == QType::SRV) {  
          pos->content = lexical_cast<string>(pos->priority) + " " + pos->content;
        }

        if(!pos->content.empty() && pos->qtype.getCode()==QType::TXT && pos->content[0]!='"') {
          pos->content="\""+pos->content+"\"";
        }
        if(pos->content.empty())  // empty contents confuse the MOADNS setup
          pos->content=".";
        shared_ptr<DNSRecordContent> drc(DNSRecordContent::mastermake(pos->qtype.getCode(), 1, pos->content)); 

	if(d_dnssecOk) {
	  if(pos != d_rrs.begin() && (signQType != pos->qtype.getCode()  || signQName != pos->qname)) {
	    addSignature(::arg()["key-repository"], signQName, wildcardQName, signQType, signTTL, signPlace, toSign, pw);
	  }
	  signQName= pos->qname;
	  wildcardQName = pos->wildcardname;
	  signQType = pos ->qtype.getCode();
	  signTTL = pos->ttl;
	  signPlace = (DNSPacketWriter::Place) pos->d_place;
	  if(pos->auth)
	    toSign.push_back(drc);
	}
	
	pw.startRecord(pos->qname, pos->qtype.getCode(), pos->ttl, pos->qclass, (DNSPacketWriter::Place)pos->d_place); 

        drc->toPacket(pw);
	
	if(!d_tcp && pw.size() + 20 > getMaxReplyLen()) {
	  cerr<<"Truncating!"<<endl;
	  pw.rollback();
	  if(pos->d_place == DNSResourceRecord::ANSWER) {
	    cerr<<"Set TC bit"<<endl;
	    pw.getHeader()->tc=1;
	  }
	  goto noCommit;

	  break;
	}
      }
      // I assume this is some dirty hack to prevent us from signing the last SOA record in an AXFR.. XXX FIXME
      if(d_dnssecOk && !(d_tcp && d_rrs.rbegin()->qtype.getCode() == QType::SOA && d_rrs.rbegin()->priority == 1234)) {
	// cerr<<"Last signature.. "<<d_tcp<<", "<<d_rrs.rbegin()->priority<<", "<<d_rrs.rbegin()->qtype.getCode()<<", "<< d_rrs.size()<<endl;
	addSignature(::arg()["key-repository"], signQName, wildcardQName, signQType, signTTL, signPlace, toSign, pw);
      }

      if(!opts.empty() || d_dnssecOk)
	pw.addOpt(2800, 0, d_dnssecOk ? EDNSOpts::DNSSECOK : 0, opts);

      pw.commit();
    noCommit:;
    }
    catch(std::exception& e) {
      L<<Logger::Warning<<"Exception: "<<e.what()<<endl;
      throw;
    }
  }
  stringbuffer.assign((char*)&packet[0], packet.size());
  len=packet.size();
}


/** Truncates a packet that has already been wrapup()-ed, possibly via a call to getData(). Do not call this function
    before having done this - it will possibly break your packet, or crash your program. 

    This method sets the 'TC' bit in the stringbuffer, and caps the len attributed to new_length.
*/ 

void DNSPacket::truncate(int new_length)
{
  if(new_length>len || !d_wrapped)
    return;

  DLOG(L<<Logger::Warning<<"Truncating a packet to "<< remote.toString() <<endl);

  len=new_length;
  stringbuffer[2]|=2; // set TC
}


void DNSPacket::setQuestion(int op, const string &qd, int newqtype)
{
  memset(&d,0,sizeof(d));
  d.id=Utility::random();
  d.rd=d.tc=d.aa=false;
  d.qr=false;
  d.qdcount=1; // is htons'ed later on
  d.ancount=d.arcount=d.nscount=0;
  d.opcode=op;
  qdomain=qd;
  qtype=newqtype;
}

/** convenience function for creating a reply packet from a question packet. Do not forget to delete it after use! */
DNSPacket *DNSPacket::replyPacket() const
{
  DNSPacket *r=new DNSPacket;
  r->setSocket(d_socket);

  r->setRemote(&remote);
  r->setAnswer(true);  // this implies the allocation of the header
  r->setA(true); // and we are authoritative
  r->setRA(0); // no recursion available
  r->setRD(d.rd); // if you wanted to recurse, answer will say you wanted it (we don't do it)
  r->setID(d.id);
  r->setOpcode(d.opcode);

  r->d_dt=d_dt;
  r->d.qdcount=1;
  r->d_tcp = d_tcp;
  r->qdomain = qdomain;
  r->qtype = qtype;
  r->qclass = qclass;
  r->d_maxreplylen = d_maxreplylen;
  r->d_ednsping = d_ednsping;
  r->d_wantsnsid = d_wantsnsid;
  r->d_dnssecOk = d_dnssecOk;
  return r;
}

void DNSPacket::spoofQuestion(const string &qd)
{
  string label=simpleCompress(qd);
  for(string::size_type i=0;i<label.size();++i)
    stringbuffer[i+sizeof(d)]=label[i];
  d_wrapped=true; // if we do this, don't later on wrapup
}

int DNSPacket::noparse(const char *mesg, int length)
{
  stringbuffer.assign(mesg,length); 
  
  len=length;
  if(length < 12) { 
    L << Logger::Warning << "Ignoring packet: too short from "
      << getRemote() << endl;
    return -1;
  }
  d_wantsnsid=false;
  d_ednsping.clear();
  d_maxreplylen=512;
  memcpy((void *)&d,(const void *)stringbuffer.c_str(),12);
  return 0;
}

/** This function takes data from the network, possibly received with recvfrom, and parses
    it into our class. Results of calling this function multiple times on one packet are
    unknown. Returns -1 if the packet cannot be parsed.
*/
int DNSPacket::parse(const char *mesg, int length)
try
{
  stringbuffer.assign(mesg,length); 
  
  len=length;
  if(length < 12) { 
    L << Logger::Warning << "Ignoring packet: too short from "
      << getRemote() << endl;
    return -1;
  }

  MOADNSParser mdp(stringbuffer);
  EDNSOpts edo;

  // ANY OPTION WHICH *MIGHT* BE SET DOWN BELOW SHOULD BE CLEARED FIRST!

  d_wantsnsid=false;
  d_dnssecOk=false;
  d_ednsping.clear();


  if(getEDNSOpts(mdp, &edo)) {
    d_maxreplylen=max(edo.d_packetsize, (uint16_t)1280);
//    cerr<<edo.d_Z<<endl;
    if(edo.d_Z & EDNSOpts::DNSSECOK)
      d_dnssecOk=true;

    for(vector<pair<uint16_t, string> >::const_iterator iter = edo.d_options.begin();
        iter != edo.d_options.end(); 
        ++iter) {
      if(iter->first == 3) {// 'EDNS NSID'
        d_wantsnsid=1;
      }
      else if(iter->first == 5) {// 'EDNS PING'
        d_ednsping = iter->second;
      }
      else
        ; // cerr<<"Have an option #"<<iter->first<<endl;
    }
  }
  else  {
    d_maxreplylen=512;
  }

  memcpy((void *)&d,(const void *)stringbuffer.c_str(),12);
  qdomain=mdp.d_qname;
  if(!qdomain.empty()) // strip dot
    boost::erase_tail(qdomain, 1);

  if(!ntohs(d.qdcount)) {
    if(!d_tcp) {
      L << Logger::Warning << "No question section in packet from " << getRemote() <<", rcode="<<(int)d.rcode<<endl;
      return -1;
    }
  }
  
  qtype=mdp.d_qtype;
  qclass=mdp.d_qclass;
  return 0;
}
catch(std::exception& e) {
  return -1;
}

int DNSPacket::getMaxReplyLen()
{
  return d_maxreplylen;
}

void DNSPacket::setMaxReplyLen(int bytes)
{
  d_maxreplylen=bytes;
}

//! Use this to set where this packet was received from or should be sent to
void DNSPacket::setRemote(const ComboAddress *s)
{
  remote=*s;
}

void DNSPacket::setSocket(Utility::sock_t sock)
{
  d_socket=sock;
}

void DNSPacket::commitD()
{
  stringbuffer.replace(0,12,(char *)&d,12); // copy in d
}

