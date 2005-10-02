/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2005  PowerDNS.COM BV

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

#include "rcpgenerator.hh"
#include "misc.hh"
#include <boost/lexical_cast.hpp>
#include <iostream>
using namespace boost;

RecordTextReader::RecordTextReader(const string& str, const string& zone) : d_string(str), d_zone(zone), d_pos(0), d_end(str.size())
{
}

void RecordTextReader::xfr32BitInt(uint32_t &val)
{
  skipSpaces();

  if(!isdigit(d_string.at(d_pos)))
    throw RecordTextException("expected digits at position "+lexical_cast<string>(d_pos)+" in '"+d_string+"'");

  char *endptr;
  unsigned long ret=strtoul(d_string.c_str() + d_pos, &endptr, 10);
  val=ret;
  
  d_pos = endptr - d_string.c_str();
}

void RecordTextReader::xfrIP(uint32_t &val)
{
  skipSpaces();

  if(!isdigit(d_string.at(d_pos)))
    throw RecordTextException("expected digits at position "+lexical_cast<string>(d_pos)+" in '"+d_string+"'");
  
  string ip;
  xfrLabel(ip);
  
  if(!IpToU32(ip, &val))
    throw RecordTextException("unable to parse IP address '"+ip+"'");
}


void RecordTextReader::xfr16BitInt(uint16_t &val)
{
  uint32_t tmp;
  xfr32BitInt(tmp);
  val=tmp;
  if(val!=tmp)
    throw RecordTextException("Overflow reading 16 bit integer from record content"); // fixme improve
}


void RecordTextReader::xfrLabel(string& val)
{
  skipSpaces();
  int pos=d_pos;
  while(d_pos < d_end && !isspace(d_string[d_pos]))
    d_pos++;

  val.assign(d_string.c_str()+pos, d_string.c_str() + d_pos);
  if(val.empty())
    val=d_zone;
  else {
    char last=val[val.size()-1];
   
    if(last != '.' && !isdigit(last)) // don't add zone to IP address
      val+="."+d_zone;
  }
}

void RecordTextReader::xfrText(string& val)
{
  skipSpaces();
  if(d_string[d_pos]!='"')
    throw RecordTextException("Data field in DNS should start with quote (\") at position "+lexical_cast<string>(d_pos)+" of '"+d_string+"'");

  val.clear();
  val.reserve(d_end - d_pos);
  
  while(++d_pos < d_end && d_string[d_pos]!='"') {
    if(d_string[d_pos]=='\\' && d_pos+1!=d_end) {
      ++d_pos;
    }
    val.append(1, d_string[d_pos]);
  }
  if(d_pos == d_end)
    throw RecordTextException("Data field in DNS should end on a quote (\") in '"+d_string+"'");
  d_pos++;

}


void RecordTextReader::skipSpaces()
{
  while(d_pos < d_end && isspace(d_string[d_pos]))
    d_pos++;

  if(d_pos == d_end)
    throw RecordTextException("missing field at the end of record content '"+d_string+"'");
}


RecordTextWriter::RecordTextWriter(string& str) : d_string(str)
{
  d_string.clear();
}

void RecordTextWriter::xfr32BitInt(const uint32_t& val)
{
  if(!d_string.empty())
    d_string.append(1,' ');
  d_string+=lexical_cast<string>(val);
}

void RecordTextWriter::xfrIP(const uint32_t& val)
{
  if(!d_string.empty())
    d_string.append(1,' ');

  ostringstream str;
  
  str<< ((val >> 24)&0xff) << ".";
  str<< ((val >> 16)&0xff) << ".";
  str<< ((val >>  8)&0xff) << ".";
  str<< ((val      )&0xff);

  d_string+=str.str();
}


void RecordTextWriter::xfr16BitInt(const uint16_t& val)
{
  xfr32BitInt(val);
}


void RecordTextWriter::xfrLabel(const string& val)
{
  if(!d_string.empty())
    d_string.append(1,' ');
  d_string+=val;
}

void RecordTextWriter::xfrText(const string& val)
{
  if(!d_string.empty())
    d_string.append(1,' ');
  d_string.append(1,'"');

  if(val.find_first_of("\\\"") == string::npos)
    d_string+=val;
  else {
    string::size_type end=val.size();
    
    for(string::size_type pos=0; pos < end; ++pos) {
      if(val[pos]=='\'' || val[pos]=='"')
	d_string.append(1,'\\');
      d_string.append(1, val[pos]);
    }
  }

  d_string.append(1,'"');
}


#ifdef TESTING

int main(int argc, char**argv)
try
{
  RecordTextReader rtr(argv[1], argv[2]);
  
  unsigned int order, pref;
  string flags, services, regexp, replacement;
  string mx;

  rtr.xfrInt(order);
  rtr.xfrInt(pref);
  rtr.xfrText(flags);
  rtr.xfrText(services);
  rtr.xfrText(regexp);
  rtr.xfrLabel(replacement);

  cout<<"order: "<<order<<", pref: "<<pref<<"\n";
  cout<<"flags: \""<<flags<<"\", services: \""<<services<<"\", regexp: \""<<regexp<<"\", replacement: "<<replacement<<"\n";

  string out;
  RecordTextWriter rtw(out);

  rtw.xfrInt(order);
  rtw.xfrInt(pref);
  rtw.xfrText(flags);
  rtw.xfrText(services);
  rtw.xfrText(regexp);
  rtw.xfrLabel(replacement);

  cout<<"Regenerated: '"<<out<<"'\n";
  
}
catch(exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}

#endif
