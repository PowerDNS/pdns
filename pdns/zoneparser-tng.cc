/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2005 - 2008  PowerDNS.COM BV

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

ZoneParserTNG::ZoneParserTNG(const string& fname, const string& zname, const string& reldir) : d_reldir(reldir), 
        										       d_zonename(zname), d_defaultttl(3600), 
        										       d_havedollarttl(false)
{
  d_zonename = toCanonic("", d_zonename);
  stackFile(fname);
}

void ZoneParserTNG::stackFile(const std::string& fname)
{
  FILE *fp=fopen(fname.c_str(), "r");
  if(!fp)
    throw runtime_error("Unable to open file '"+fname+"': "+stringerror());

  filestate fs(fp, fname);
  d_filestates.push(fs);
}

ZoneParserTNG::~ZoneParserTNG()
{
  while(!d_filestates.empty()) {
    fclose(d_filestates.top().d_fp);
    d_filestates.pop();
  }
}

static string makeString(const string& line, const pair<string::size_type, string::size_type>& range)
{
  return string(line.c_str() + range.first, range.second - range.first);
}

static bool isTimeSpec(const string& nextpart)
{
  if(nextpart.empty())
    return false;
  for(string::const_iterator iter = nextpart.begin(); iter != nextpart.end(); ++iter) {
    if(isdigit(*iter))
      continue;
    if(iter+1 != nextpart.end())
      return false;
    char c=tolower(*iter);
    return (c=='s' || c=='m' || c=='h' || c=='d' || c=='w' || c=='y');
  }
  return true;
}


unsigned int ZoneParserTNG::makeTTLFromZone(const string& str)
{
  if(str.empty())
    return 0;

  unsigned int val=atoi(str.c_str());
  char lc=toupper(str[str.length()-1]);
  if(!isdigit(lc))
    switch(lc) {
    case 'S':
      break;
    case 'M':
      val*=60; // minutes, not months!
      break;
    case 'H':
      val*=3600;
      break;
    case 'D':
      val*=3600*24;
      break;
    case 'W':
      val*=3600*24*7;
      break;
    case 'Y': // ? :-)
      val*=3600*24*365;
      break;

    default:
      throw ZoneParserTNG::exception("Unable to parse time specification '"+str+"' "+getLineOfFile());
    }
  return val;
}

bool ZoneParserTNG::getTemplateLine()
{
  if(d_templateparts.empty() || d_templatecounter > d_templatestop) // no template, or done with
    return false;

  string retline;
  for(parts_t::const_iterator iter = d_templateparts.begin() ; iter != d_templateparts.end(); ++iter) {
    if(iter != d_templateparts.begin())
      retline+=" ";

    string part=makeString(d_templateline, *iter);
    
    /* a part can contain a 'naked' $, an escaped $ (\$), or ${offset,width,radix}, with width defaulting to 0, 
       and radix beging 'd', 'o', 'x' or 'X', defaulting to 'd'. 

       The width is zero-padded, so if the counter is at 1, the offset is 15, with is 3, and the radix is 'x',
       output will be '010', from the input of ${15,3,x}
    */

    string outpart;
    outpart.reserve(part.size()+5);
    bool inescape=false;

    for(string::size_type pos = 0; pos < part.size() ; ++pos) {
      char c=part[pos];
      if(inescape) {
        outpart.append(1, c);
        inescape=false;
        continue;
      }
        
      if(part[pos]=='\\') {
        inescape=true;
        continue;
      }
      if(c=='$') {
        if(pos + 1 == part.size() || part[pos+1]!='{') {  // a trailing $, or not followed by {
          outpart.append(lexical_cast<string>(d_templatecounter));
          continue;
        }
        
        // need to deal with { case 
        
        pos+=2;
        string::size_type startPos=pos;
        for(; pos < part.size() && part[pos]!='}' ; ++pos)
          ;
        
        if(pos == part.size()) // partial spec
          break;

        // we are on the '}'

        string spec(part.c_str() + startPos, part.c_str() + pos);
        int offset=0, width=0;
        char radix='d';
        sscanf(spec.c_str(), "%d,%d,%c", &offset, &width, &radix);  // parse format specifier

        char format[12];
        snprintf(format, sizeof(format) - 1, "%%0%d%c", width, radix); // make into printf-style format

        char tmp[80];
        snprintf(tmp, sizeof(tmp)-1, format, d_templatecounter + offset); // and do the actual printing
        outpart+=tmp;
      }
      else
        outpart.append(1, c);
    }
    retline+=outpart;
  }
  d_templatecounter+=d_templatestep;

  d_line = retline;
  return true;
}

void chopComment(string& line)
{
  string::size_type pos, len = line.length();
  bool inQuote=false;
  for(pos = 0 ; pos < len; ++pos) {
    if(line[pos]=='\\') 
      pos++;
    else if(line[pos]=='"') 
      inQuote=!inQuote;
    else if(line[pos]==';' && !inQuote)
      break;
  }
  if(pos != len)
    line.resize(pos);
}

bool findAndElide(string& line, char c)
{
  string::size_type pos, len = line.length();
  bool inQuote=false;
  for(pos = 0 ; pos < len; ++pos) {
    if(line[pos]=='\\') 
      pos++;
    else if(line[pos]=='"') 
      inQuote=!inQuote;
    else if(line[pos]==c && !inQuote)
      break;
  }
  if(pos != len) {
    line.erase(pos, 1);
    return true;
  }
  return false;
}

string ZoneParserTNG::getLineOfFile()
{
  return "on line "+lexical_cast<string>(d_filestates.top().d_lineno)+" of file '"+d_filestates.top().d_filename+"'";
}

// ODD: this function never fills out the prio field! rest of pdns compensates though
bool ZoneParserTNG::get(DNSResourceRecord& rr) 
{
 retry:;
  if(!getTemplateLine() && !getLine())
    return false;

  boost::trim_right_if(d_line, is_any_of(" \r\n\x1a"));

  parts_t parts;
  vstringtok(parts, d_line);

  if(parts.empty())
    goto retry;

  if(parts[0].first != parts[0].second && makeString(d_line, parts[0])[0]==';') // line consisting of nothing but comments
    goto retry;

  if(d_line[0]=='$') { 
    string command=makeString(d_line, parts[0]);
    if(pdns_iequals(command,"$TTL") && parts.size() > 1) {
      d_defaultttl=makeTTLFromZone(trim_right_copy_if(makeString(d_line, parts[1]), is_any_of(";")));
      d_havedollarttl=true;
    }
    else if(pdns_iequals(command,"$INCLUDE") && parts.size() > 1) {
      string fname=unquotify(makeString(d_line, parts[1]));
      if(!fname.empty() && fname[0]!='/' && !d_reldir.empty())
        fname=d_reldir+"/"+fname;
      stackFile(fname);
    }
    else if(pdns_iequals(command, "$ORIGIN") && parts.size() > 1) {
      d_zonename = toCanonic("", makeString(d_line, parts[1]));
    }
    else if(pdns_iequals(command, "$GENERATE") && parts.size() > 2) {
      // $GENERATE 1-127 $ CNAME $.0
      string range=makeString(d_line, parts[1]);
      d_templatestep=1;
      d_templatestop=0;
      sscanf(range.c_str(),"%d-%d/%d", &d_templatecounter, &d_templatestop, &d_templatestep);
      d_templateline=d_line;
      parts.pop_front();
      parts.pop_front();

      d_templateparts=parts;
      goto retry;
    }
    else
      throw exception("Can't parse zone line '"+d_line+"' "+getLineOfFile());
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
    if(d_zonename.empty() || d_zonename[0]!='.') // prevent us from adding a double dot
      rr.qname.append(1,'.');
    
    rr.qname.append(d_zonename);
  }
  d_prevqname=rr.qname;

  if(parts.empty()) 
    throw exception("Line with too little parts "+getLineOfFile());

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
    
    if(pdns_iequals(nextpart, "IN")) {
      // cout<<"Ignoring 'IN'\n";
      continue;
    }
    if(!haveTTL && !haveQTYPE && isTimeSpec(nextpart)) {
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
      throw runtime_error("Parsing zone content "+getLineOfFile()+
        		  ": '"+nextpart+
        		  "' doesn't look like a qtype, stopping loop");
    }
  }
  if(!haveQTYPE) 
    throw exception("Malformed line "+getLineOfFile()+": '"+d_line+"'");

  rr.content=d_line.substr(range.first);

  chopComment(rr.content);
  trim(rr.content);

  if(equals(rr.content, "@"))
    rr.content=d_zonename;

  if(findAndElide(rr.content, '(')) {      // have found a ( and elided it
    if(!findAndElide(rr.content, ')')) {
      while(getLine()) {
        trim_right(d_line);
        chopComment(d_line);
        trim(d_line);
        
        bool ended = findAndElide(d_line, ')');
        rr.content+=" "+d_line;
        if(ended)
          break;
      }
    }
  }

  vector<string> recparts;
  switch(rr.qtype.getCode()) {
  case QType::MX:
    stringtok(recparts, rr.content);
    if(recparts.size()==2) {
      recparts[1] = stripDot(toCanonic(d_zonename, recparts[1]));
      rr.content=recparts[0]+" "+recparts[1];
    }
    break;
  
  case QType::SRV:
    stringtok(recparts, rr.content);
    if(recparts.size()==4) {
      recparts[3] = stripDot(toCanonic(d_zonename, recparts[3]));
      rr.content=recparts[0]+" "+recparts[1]+" "+recparts[2]+" "+recparts[3];
    }
    break;
  
    
  case QType::NS:
  case QType::CNAME:
  case QType::PTR:
  case QType::AFSDB:
    rr.content=stripDot(toCanonic(d_zonename, rr.content));
    break;

  case QType::SOA:
    stringtok(recparts, rr.content);
    if(recparts.size() > 1) {
      recparts[0]=toCanonic(d_zonename, recparts[0]);
      recparts[1]=toCanonic(d_zonename, recparts[1]);
    }
    rr.content.clear();
    for(string::size_type n = 0; n < recparts.size(); ++n) {
      if(n)
        rr.content.append(1,' ');

      if(n > 1)
        rr.content+=lexical_cast<string>(makeTTLFromZone(recparts[n]));
      else
        rr.content+=recparts[n];

      if(n==6 && !d_havedollarttl)
        d_defaultttl=makeTTLFromZone(recparts[n]);
    }
    break;
  default:;
  }

  rr.d_place=DNSResourceRecord::ANSWER;
  return true;
}


bool ZoneParserTNG::getLine()
{
  while(!d_filestates.empty()) {
    if(stringfgets(d_filestates.top().d_fp, d_line)) {
      d_filestates.top().d_lineno++;
      return true;
    }
    fclose(d_filestates.top().d_fp);
    d_filestates.pop();
  }
  return false;
}
