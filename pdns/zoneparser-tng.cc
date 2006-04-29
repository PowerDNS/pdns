/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2005 - 2006  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 
    as published by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "misc.hh"
#include <fstream>
#include "dns.hh"
#include "zoneparser-tng.hh"
#include <deque>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

ZoneParserTNG::ZoneParserTNG(const string& fname, const string& zname) : d_zonename(zname), d_defaultttl(3600)
{
  d_fp=fopen(fname.c_str(), "r");
  if(!d_fp)
    throw runtime_error("Unable to open file '"+fname+"': "+stringerror());
}

ZoneParserTNG::~ZoneParserTNG()
{
  fclose(d_fp);
}

static string makeString(const string& line, const pair<string::size_type, string::size_type>& range)
{
  return string(line.c_str() + range.first, range.second - range.first);
}

static unsigned int makeTTLFromZone(const string& str)
{
  if(str.empty())
    return 0;

  unsigned int val=atoi(str.c_str());
  char lc=toupper(str[str.length()-1]);
  if(!isdigit(lc))
    switch(lc) {
    case 'H':
      val*=3600;
      break;
    case 'D':
      val*=3600*24;
      break;
    case 'W':
      val*=3600*24*7;
      break;
    case 'M':
      val*=3600*24*7*4;
      break;
    case 'Y': // ? :-)
      val*=3600*24*365;
      break;
    default:
      throw ZoneParserTNG::exception("Unable to parse time specification '"+str+"'");
    }
  return val;
}

bool ZoneParserTNG::get(DNSResourceRecord& rr) 
{
 retry:;
  if(!getLine())
    return false;

  chomp(d_line, " \r\n\x1a");
  deque<pair<string::size_type, string::size_type> > parts;
  vstringtok(parts, d_line);

  if(parts.empty())
    goto retry;

  if(d_line[0]=='$') { 
    if(makeString(d_line, parts[0])=="$TTL" && parts.size() > 1)
      d_defaultttl=makeTTLFromZone(makeString(d_line,parts[1]));
    else
      throw exception("Can't parse zone line '"+d_line+"'");
    goto retry;
  }


  if(isspace(d_line[0])) 
    rr.qname=d_prevqname;
  else {
    rr.qname=makeString(d_line, parts[0]); 
    parts.pop_front();
    if(rr.qname.empty() || rr.qname[0]==';')
      goto retry;
  }
  if(rr.qname=="@")
    rr.qname=d_zonename;
  else if(!isCanonical(rr.qname)) {
    rr.qname.append(1,'.');
    rr.qname.append(d_zonename);
  }
  d_prevqname=rr.qname;

  if(parts.empty()) 
    throw exception("Line with too little parts");

  // cout<<"Have qname: '"<<rr.qname<<"'\n";

  string nextpart;
  
  rr.ttl=d_defaultttl;
  bool haveTTL=0, haveQTYPE=0;
  pair<string::size_type, string::size_type> range;

  while(!parts.empty()) {
    range=parts.front();
    parts.pop_front();
    nextpart=makeString(d_line, range);
    if(nextpart.empty())
      break;

    if(nextpart.find(';')!=string::npos)
      break;

    // cout<<"Next part: '"<<nextpart<<"'"<<endl;
    
    if(!Utility::strcasecmp(nextpart.c_str(), "IN")) {
      // cout<<"Ignoring 'IN'\n";
      continue;
    }
    if(!haveTTL && !haveQTYPE && all(nextpart, is_digit())) {
      rr.ttl=makeTTLFromZone(nextpart);
      haveTTL=true;
      // cout<<"ttl is probably: "<<rr.ttl<<endl;
      continue;
    }
    if(haveQTYPE) 
      break;

    try {
      rr.qtype=DNSRecordContent::TypeToNumber(nextpart);
      // cout<<"Got qtype ("<<rr.qtype.getCode()<<")\n";
      haveQTYPE=1;
      continue;
    }
    catch(...) {
      cerr<<"Oops, this doesn't look like a qtype, stopping loop\n";
      break;
    }
  }
  if(!haveQTYPE) 
    throw exception("Malformed line '"+d_line+"'");

  rr.content=d_line.substr(range.first);

  string::size_type pos=rr.content.rfind(';');
  if(pos!=string::npos)
    rr.content.resize(pos);

  if(rr.qtype.getCode()!=QType::TXT && (pos=rr.content.find('('))!=string::npos) {
    rr.content.resize(pos); // chop off (
    trim(rr.content);
    while(getLine()) {
      chomp(d_line,"\r\n ");
      pos=d_line.rfind(';');
      if(pos!=string::npos)
	d_line.resize(pos);

      trim(d_line);
      
      pos=d_line.find(')');
      if(pos!=string::npos) {
	d_line.resize(pos);
	trim(d_line);
	rr.content+=" "+d_line;
	break;
      }
      rr.content+=" "+d_line;
    }
  }
  vector<string> soaparts;
  switch(rr.qtype.getCode()) {
  case QType::MX:
  case QType::NS:
  case QType::CNAME:
  case QType::PTR:
  case QType::SRV:
    rr.content=toCanonic(d_zonename, rr.content);
    break;

  case QType::SOA:
    stringtok(soaparts, rr.content);
    if(soaparts.size() > 1) {
      soaparts[0]=toCanonic(d_zonename, soaparts[0]);
      soaparts[1]=toCanonic(d_zonename, soaparts[1]);
    }
    rr.content.clear();
    for(string::size_type n = 0; n < soaparts.size(); ++n) {
      if(n)
	rr.content.append(1,' ');
      rr.content+=soaparts[n];
    }
  default:;
  }

  rr.d_place=DNSResourceRecord::ANSWER;
  return true;
}

bool ZoneParserTNG::getLine()
{
  char buffer[1024];
  if(fgets(buffer, 1024, d_fp)) {
    d_line=buffer;
    return true;
  }
  return false;
}


#if 0
int main(int argc, char** argv)
try
{
  reportAllTypes();
  ZoneParserTNG zpt(argv[1]);
  DNSResourceRecord rr;
  while(zpt.get(rr)) {
  }
  

}
catch(...)
{}
#endif
