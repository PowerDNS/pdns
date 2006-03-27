/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2005  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 
    as published by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

ZoneParserTNG::ZoneParserTNG(const string& fname)
{
  d_fp=fopen(fname.c_str(), "r");
  if(!d_fp)
    throw runtime_error("Unable to open file '"+fname+"': "+stringerror());
}

ZoneParserTNG::~ZoneParserTNG()
{
  fclose(d_fp);
}

bool ZoneParserTNG::get(DNSResourceRecord& rr) 
{
 retry:;
  if(!getLine())
    return false;
  string::size_type pos;
  vector<string> parts;
  
  if((pos=d_line.find(';'))!=string::npos)
    d_line.resize(pos);
  stripLine(d_line);
  if(d_line.empty())
    goto retry;
  
  parts.clear();
  stringtok(parts, d_line);
  if(parts.size()!=4 && parts.size()!=5) {
    cerr<<"Bad line: '"<<d_line<<"'\n";
    return false;
  }
  
  rr.qname=toLowerCanonic(parts[0]);
  rr.ttl=atoi(parts[1].c_str());
  string qclass("IN");
  
  rr.qtype=parts[2 + (parts.size()==5)];
  rr.content=parts[3 + (parts.size()==5)];
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
