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
#include "ascii.hh"
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
#include <system_error>

static string g_INstr("IN");

ZoneParserTNG::ZoneParserTNG(const string& fname, const DNSName& zname, const string& reldir) : d_reldir(reldir), 
                                                                                               d_zonename(zname), d_defaultttl(3600), 
                                                                                               d_templatecounter(0), d_templatestop(0),
                                                                                               d_templatestep(0), d_havedollarttl(false){
  stackFile(fname);
}

ZoneParserTNG::ZoneParserTNG(const vector<string> zonedata, const DNSName& zname):
  d_zonename(zname), d_zonedata(zonedata), d_defaultttl(3600),
  d_templatecounter(0), d_templatestop(0), d_templatestep(0),
  d_havedollarttl(false), d_fromfile(false)
{
  d_zonedataline = d_zonedata.begin();
}

void ZoneParserTNG::stackFile(const std::string& fname)
{
  FILE *fp=fopen(fname.c_str(), "r");
  if(!fp) {
    std::error_code ec (errno,std::generic_category());
    throw std::system_error(ec, "Unable to open file '"+fname+"': "+stringerror());
  }

  filestate fs(fp, fname);
  d_filestates.push(fs);
  d_fromfile = true;
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

  unsigned int val;
  try {
    val=pdns_stou(str);
  }
  catch (const std::out_of_range& oor) {
    throw PDNSException("Unable to parse time specification '"+str+"' "+getLineOfFile());
  }

  char lc=dns_tolower(str[str.length()-1]);
  if(!isdigit(lc))
    switch(lc) {
    case 's':
      break;
    case 'm':
      val*=60; // minutes, not months!
      break;
    case 'h':
      val*=3600;
      break;
    case 'd':
      val*=3600*24;
      break;
    case 'w':
      val*=3600*24*7;
      break;
    case 'y': // ? :-)
      val*=3600*24*365;
      break;

    default:
      throw PDNSException("Unable to parse time specification '"+str+"' "+getLineOfFile());
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
       and radix being 'd', 'o', 'x' or 'X', defaulting to 'd'. 

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
          outpart.append(std::to_string(d_templatecounter));
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

        char tmp[80];
        switch (radix) {
        case 'o':
          snprintf(tmp, sizeof(tmp), "%0*o", width, d_templatecounter + offset);
          break;
        case 'x':
          snprintf(tmp, sizeof(tmp), "%0*x", width, d_templatecounter + offset);
          break;
        case 'X':
          snprintf(tmp, sizeof(tmp), "%0*X", width, d_templatecounter + offset);
          break;
        case 'd':
        default:
          snprintf(tmp, sizeof(tmp), "%0*d", width, d_templatecounter + offset);
          break;
        }
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
  if(line.find(';')==string::npos)
    return;
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

DNSName ZoneParserTNG::getZoneName()
{
  return d_zonename;
}

string ZoneParserTNG::getLineOfFile()
{
  if (d_zonedata.size() > 0)
    return "on line "+std::to_string(std::distance(d_zonedata.begin(), d_zonedataline))+" of given string";

  if (d_filestates.empty())
    return "";

  return "on line "+std::to_string(d_filestates.top().d_lineno)+" of file '"+d_filestates.top().d_filename+"'";
}

pair<string,int> ZoneParserTNG::getLineNumAndFile()
{
  if (d_filestates.empty())
    return {"", 0};
  else
    return {d_filestates.top().d_filename, d_filestates.top().d_lineno};
}

bool ZoneParserTNG::get(DNSResourceRecord& rr, std::string* comment)
{
 retry:;
  if(!getTemplateLine() && !getLine())
    return false;

  boost::trim_right_if(d_line, is_any_of(" \t\r\n\x1a"));
  if(comment)
    comment->clear();
  if(comment && d_line.find(';') != string::npos)
    *comment = d_line.substr(d_line.find(';'));
  parts_t parts;
  vstringtok(parts, d_line);

  if(parts.empty())
    goto retry;

  if(parts[0].first != parts[0].second && d_line[parts[0].first]==';') // line consisting of nothing but comments
    goto retry;

  if(d_line[0]=='$') { 
    string command=makeString(d_line, parts[0]);
    if(pdns_iequals(command,"$TTL") && parts.size() > 1) {
      d_defaultttl=makeTTLFromZone(trim_right_copy_if(makeString(d_line, parts[1]), is_any_of(";")));
      d_havedollarttl=true;
    }
    else if(pdns_iequals(command,"$INCLUDE") && parts.size() > 1 && d_fromfile) {
      string fname=unquotify(makeString(d_line, parts[1]));
      if(!fname.empty() && fname[0]!='/' && !d_reldir.empty())
        fname=d_reldir+"/"+fname;
      stackFile(fname);
    }
    else if(pdns_iequals(command, "$ORIGIN") && parts.size() > 1) {
      d_zonename = DNSName(makeString(d_line, parts[1]));
    }
    else if(pdns_iequals(command, "$GENERATE") && parts.size() > 2) {
      // $GENERATE 1-127 $ CNAME $.0
      string range=makeString(d_line, parts[1]);
      d_templatestep=1;
      d_templatestop=0;
      sscanf(range.c_str(),"%u-%u/%u", &d_templatecounter, &d_templatestop, &d_templatestep);
      if (d_templatestep < 1 ||
          d_templatestop < d_templatecounter) {
        throw exception("Invalid $GENERATE parameters");
      }
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

  bool prevqname=false;
  string qname = makeString(d_line, parts[0]); // Don't use DNSName here!
  if(dns_isspace(d_line[0])) {
    rr.qname=d_prevqname;
    prevqname=true;
  }else {
    rr.qname=DNSName(qname); 
    parts.pop_front();
    if(qname.empty() || qname[0]==';')
      goto retry;
  }
  if(qname=="@")
    rr.qname=d_zonename;
  else if(!prevqname && !isCanonical(qname))
    rr.qname += d_zonename;
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

    if(nextpart.find(';')!=string::npos) {
      break;
    }

    // cout<<"Next part: '"<<nextpart<<"'"<<endl;

    if(pdns_iequals(nextpart, g_INstr)) {
      // cout<<"Ignoring 'IN'\n";
      continue;
    }
    if(!haveTTL && !haveQTYPE && isTimeSpec(nextpart)) {
      rr.ttl=makeTTLFromZone(nextpart);
      if(!d_havedollarttl)
        d_defaultttl = rr.ttl;
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

  //  rr.content=d_line.substr(range.first);
  rr.content.assign(d_line, range.first, string::npos);
  chopComment(rr.content);
  trim_if(rr.content, is_any_of(" \r\n\t\x1a"));

  if(rr.content.size()==1 && rr.content[0]=='@')
    rr.content=d_zonename.toString();

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
  trim_if(rr.content, is_any_of(" \r\n\t\x1a"));

  vector<string> recparts;
  switch(rr.qtype.getCode()) {
  case QType::MX:
    stringtok(recparts, rr.content);
    if(recparts.size()==2) {
      if (recparts[1]!=".") {
        try {
          recparts[1] = toCanonic(d_zonename, recparts[1]).toStringRootDot();
        } catch (std::exception &e) {
          throw PDNSException("Error in record '" + rr.qname.toLogString() + " " + rr.qtype.getName() + "': " + e.what());
        }
      }
      rr.content=recparts[0]+" "+recparts[1];
    }
    break;
  
  case QType::RP:
    stringtok(recparts, rr.content);
    if(recparts.size()==2) {
      recparts[0] = toCanonic(d_zonename, recparts[0]).toStringRootDot();
      recparts[1] = toCanonic(d_zonename, recparts[1]).toStringRootDot();
      rr.content=recparts[0]+" "+recparts[1];
    }
    break;

  case QType::SRV:
    stringtok(recparts, rr.content);
    if(recparts.size()==4) {
      if(recparts[3]!=".") {
        try {
          recparts[3] = toCanonic(d_zonename, recparts[3]).toStringRootDot();
        } catch (std::exception &e) {
          throw PDNSException("Error in record '" + rr.qname.toLogString() + " " + rr.qtype.getName() + "': " + e.what());
        }
      }
      rr.content=recparts[0]+" "+recparts[1]+" "+recparts[2]+" "+recparts[3];
    }
    break;
  
    
  case QType::NS:
  case QType::CNAME:
  case QType::DNAME:
  case QType::PTR:
    try {
      rr.content = toCanonic(d_zonename, rr.content).toStringRootDot();
    } catch (std::exception &e) {
      throw PDNSException("Error in record '" + rr.qname.toLogString() + " " + rr.qtype.getName() + "': " + e.what());
    }
    break;
  case QType::AFSDB:
    stringtok(recparts, rr.content);
    if(recparts.size() == 2) {
      try {
        recparts[1]=toCanonic(d_zonename, recparts[1]).toStringRootDot();
      } catch (std::exception &e) {
        throw PDNSException("Error in record '" + rr.qname.toLogString() + " " + rr.qtype.getName() + "': " + e.what());
      }
    } else {
      throw PDNSException("AFSDB record for "+rr.qname.toLogString()+" invalid");
    }
    rr.content.clear();
    for(string::size_type n = 0; n < recparts.size(); ++n) {
      if(n)
        rr.content.append(1,' ');

      rr.content+=recparts[n];
    }
    break;
  case QType::SOA:
    stringtok(recparts, rr.content);
    if(recparts.size() > 7)
      throw PDNSException("SOA record contents for "+rr.qname.toLogString()+" contains too many parts");
    if(recparts.size() > 1) {
      try {
        recparts[0]=toCanonic(d_zonename, recparts[0]).toStringRootDot();
        recparts[1]=toCanonic(d_zonename, recparts[1]).toStringRootDot();
      } catch (std::exception &e) {
        throw PDNSException("Error in record '" + rr.qname.toLogString() + " " + rr.qtype.getName() + "': " + e.what());
      }
    }
    rr.content.clear();
    for(string::size_type n = 0; n < recparts.size(); ++n) {
      if(n)
        rr.content.append(1,' ');

      if(n > 1)
        rr.content+=std::to_string(makeTTLFromZone(recparts[n]));
      else
        rr.content+=recparts[n];
    }
    break;
  default:;
  }
  return true;
}


bool ZoneParserTNG::getLine()
{
  if (d_zonedata.size() > 0) {
    if (d_zonedataline != d_zonedata.end()) {
      d_line = *d_zonedataline;
      ++d_zonedataline;
      return true;
    }
    return false;
  }
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
