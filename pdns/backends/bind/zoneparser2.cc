/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifdef WIN32
# pragma warning ( disable: 4786 )
#endif // WIN32

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <iostream>
#include <utility>
#include <ctype.h>
#include <errno.h>
#include <stack>
#include "utility.hh"
#include "misc.hh"
#include "ahuexception.hh"
#include <algorithm>
using namespace std;

#include "zoneparser.hh"

extern const char *bind_directory;
void ZoneParser::setDirectory(const string &dir)
{
  d_dir=dir;

}

void ZoneParser::parse(const string &fname, const string &origin)
{	
  d_filename=fname.c_str();

  FILE *zonein=fopen(fname.c_str(),"r");

  if(!zonein)
    throw AhuException("Unable to open zonefile '"+fname+"': "+stringerror());

  d_origin=origin;
  
  char line[2048];
  d_lineno=0;
  vector<Record> rec;
  stack<FILE *>fds;
  fds.push(zonein);
  while(!fds.empty()) {
    while(fgets(line,2047,fds.top())) {
      d_lineno++;
      if(strstr(line, "$INCLUDE ")==line) {
	vector<string> parts;
	stringtok(parts,line," \t\n"); 
	if(parts.size()!=2)
	  throw AhuException("Invalid $INCLUDE statement in zonefile '"+fname+"'");
	
	string filename=parts[1];
	if(filename[0]!='/')
	  filename=d_dir+"/"+filename;


	FILE *fp=fopen(filename.c_str(),"r");
	if(!fp)
	  throw AhuException("Unable to open zonefile '"+filename+"' included from '"+fname+"': "+stringerror());
	fds.push(fp);
	continue;
      }
      if(eatLine(line,rec))
	for(vector<Record>::const_iterator i=rec.begin();i!=rec.end();++i)
	  d_callback(i->name, i->qtype,i->content,i->ttl,i->prio);
    }
    fclose(fds.top());
    fds.pop();
  }
}


void ZoneParser::fillRec(const string &qname, const string &qtype, const string &content, int ttl, int prio, vector<Record>&recs)
{
  Record rec;
  rec.name=qname;
  rec.qtype=qtype;
  rec.content=content;
  rec.ttl=ttl;
  rec.prio=prio;
  recs.push_back(rec);

}

void ZoneParser::parse(const string &fname, const string &origin, vector<Record>&records)
{	
  d_filename=fname.c_str();

  FILE *zonein=fopen(fname.c_str(),"r");

  if(!zonein)
    throw AhuException("Unable to open zonefile '"+fname+"': "+stringerror());

  d_origin=origin;
  
  char line[2048];
  d_lineno=0;
  vector<Record> rec;
  stack<FILE *>fds;
  fds.push(zonein);
  while(!fds.empty()) {
    while(fgets(line,2047,fds.top())) {
      d_lineno++;
      if(strstr(line, "$INCLUDE ")==line) {
	vector<string> parts;
	stringtok(parts,line," \t\n");
	if(parts.size()!=2)
	  throw AhuException("Invalid $INCLUDE statement in zonefile '"+fname+"'");


	FILE *fp=fopen(parts[1].c_str(),"r");
	if(!fp)
	  throw AhuException("Unable to open zonefile '"+parts[1]+"' included from '"+parts[1]+"': "+stringerror());
	fds.push(fp);
	continue;
      }
      if(eatLine(line,rec))
	for(vector<Record>::const_iterator i=rec.begin();i!=rec.end();++i)
	  records.push_back(*i);
    }
    fclose(fds.top());
    fds.pop();
  }
  

}

void ZoneParser::cutOff(string &line, const string &delim)
{
  unsigned int pos=line.find_first_of(delim);
  if(pos==string::npos)
    return;
  line=line.substr(0,pos);
}

bool ZoneParser::eatLine(string line, vector<Record> &rec)
{

  rec.clear();
  static string tline;
  static string lastfirstword;
  chomp(line," \x1a\r\n");
  cutOff(line,";");
  unsigned int pos=string::npos;

  if(tline.empty()) {
    pos=line.find("(");
    if(pos!=string::npos) { // this is a line that continues
      tline=line.substr(0,pos);
      return false;
    }
    else 
      tline=line; // complete & boring line
  }
  else { // continuation
    pos=line.find(")");
    if(pos==string::npos) { // middle part
      tline.append(line);
      return false;
    }
    else {
      tline.append(line.substr(0,pos)); // end part, we have a complete line!
    }
  }
  
  // full & unparenthesised line now in tline!
  //  cout<<"line: '"<<tline<<"'"<<endl;
  if(tline.empty() || tline.find_first_not_of(" \t\n")==string::npos) {

    tline="";
    return false;
  }

  if(isspace(tline[0]))
    tline=lastfirstword+"\t"+tline;

  vector<string> parts;
  stringtok(parts,tline," \t\"");  // THIS IS WRONG, THE " SHOULD BE TREATED! XXX FIXME
  if(parts[0][0]!='$' && !isspace(parts[0][0]))
    lastfirstword=parts[0];

  //  for_each(parts.begin(),parts.end(),print);
  tline="";
  return parseLine(parts,rec);
}

ZoneParser::~ZoneParser()
{

}

void ZoneParser::setCallback(callback_t *callback)
{
	d_callback=callback;
}

bool ZoneParser::isNumber(const string &s)
{
  for(string::const_iterator i=s.begin();
      i!=s.end();
      ++i) {
    if(i+1==s.end())
      if(*i=='M' || *i=='D' || *i=='H' || *i=='W' || *i=='m' || *i=='d' || *i=='h' || *i=='w') // last character
	continue;
    if(!isdigit(*i))
      return false;
  }
  return true;
}

bool ZoneParser::isType(const string &s)
{
  if(isNumber(s))
    return false;

  if(isClass(s))
    return false;


  return true;
}

bool ZoneParser::isClass(const string &s)
{
  return (s=="IN" || s=="CH" || s=="HS");
}

unsigned int ZoneParser::zoneNumber(const string &str)
{
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
      throw AhuException("Unable to parse "+d_origin+" time specification '"+str+"'");
    }
  return val;

}

/** this parser handles 10 cases (sigh)
    1) qname TTL CLASS QTYPE *
    2) qname CLASS TTL QTYPE *
    3) qname CLASS QTYPE *
    4) qname TTL QTYPE *
    5) qname QTYPE *

    And then everything again with a space first character, which implies 'same as last name'
*/

void ZoneParser::soaCanonic(string &content)
{
  vector<string>parts;
  stringtok(parts,content," \t");
  int pos=0;

  // 'ns.naamserver.net. hostmaster.naamserver.net 2001102501 8H 2H 1W 1D'

  string newcontent;
  for(vector<string>::const_iterator i=parts.begin();i!=parts.end();++i,++pos) {
    if(pos<3) {
      if(pos)
	newcontent.append(1,' ');
      newcontent.append(*i);
    }
    else {
      unsigned int val=zoneNumber(*i);

      newcontent.append(1,' ');
      newcontent.append(itoa(val));
    }
  }
  content=newcontent;
}

string ZoneParser::expandWord(const string &line, int value)
{
  string newline;
  bool escape=false;
  for(string::const_iterator i=line.begin();i!=line.end();++i) {
    if(*i=='\\')
      escape=true;
    else{
      if(!escape && *i=='$') {
	if(i+2<line.end() && *(i+1)=='{') { // shit
	  string::const_iterator k=(i+=2);
	  while(k++!=line.end() && *k!='}')
	    ;
	  if(k==line.end())
	    throw AhuException("Malformed $GENERATE statement");

	  string spec;
	  
	  //copy(i,k,back_inserter(spec));
    for ( string::const_iterator a = i; a != k; ++a )
      spec += *a;

	  vector<string> partjes;
	  stringtok(partjes,spec,",");
	  if(partjes.empty())
	    throw AhuException("Malformed $GENERATE statement: '"+spec+"'");
	  
	  value+=atoi(partjes[0].c_str());
	  int width=0;
	  char radix='d';
	  if(partjes.size()>=2)
	    width=atoi(partjes[1].c_str());
	  if(partjes.size()>=3)
	    radix=partjes[2][0];

	  char tmp[20];
	  string format;
	  format="%0";
	  format+=itoa(width);
	  format.append(1,radix);
	  
	  snprintf(tmp,19,format.c_str(),value);

	  newline.append(tmp);
	  i=k;
	}
	else
	  newline.append(itoa(value));
      }
      else
	newline.append(1,*i);
      escape=false;
    }
  }
  return newline;
}

string ZoneParser::canonic(const string& dom)
{
  if(dom[dom.size()-1]!='.')
    return dom;

  return dom.substr(0,dom.size()-1);

}


bool ZoneParser::parseLine(const vector<string>&words, vector<Record>&rec)
{
  int cpos=0;
  if(!words.size())
    return false;

  if(words[0][0]=='$')
    {
    if(!Utility::strcasecmp(words[0].c_str(),"$ORIGIN") && words.size()>1) {
	d_origin=canonic(words[1]);
      }
      else if(!Utility::strcasecmp(words[0].c_str(),"$TTL") && words.size()>1) {
	d_ttl=zoneNumber(words[1]);
      }
      else if(!Utility::strcasecmp(words[0].c_str(),"$GENERATE") && words.size()>1) {
	// $GENERATE 1-127 $ CNAME $.0
	string range=words[1];  // 1-127 means 1...127 (including 127). 1-127/2 is 1..3..5..
	vector<string>parts;
	stringtok(parts,range,"-/");
	if(parts.size()<2 || parts.size()>3)
	  throw AhuException("Malformed $GENERATE on line "+itoa(d_lineno)+" of "+d_filename);

	int start, stop, step=1;
	start=atoi(parts[0].c_str());
	stop=atoi(parts[1].c_str());
	if(parts.size()==3)
	  step=atoi(parts[2].c_str());
	vector<string>newwords;

	for(int i=start;i<stop;++i) {
	  newwords.clear();
	  for(unsigned int j=2;j<words.size();++j) {
	    newwords.push_back(expandWord(words[j],i));
	  }
	  parseLine(newwords, rec);
	}
	return true;
      }
      else {
	throw AhuException("Unhandled command '"+words[0]+"' on line "+itoa(d_lineno)+" of "+d_filename);
      }
      
      return false;

    }
  if(words.size()<3) {
    if(words.size()==1 && words[0]==";")
      return false;
    throw AhuException("Short line "+itoa(d_lineno)+": "+itoa(words.size())+ " words. Probably due to repeated record without domainname");
  }

  string qname=words[0];
  string qclass="IN";
  int ttl=d_ttl;
  string qtype="NONE";
  if(isNumber(words[1])) // 1 || 4
    {
      ttl=zoneNumber(words[1]);
      if(isClass(words[2])) 
	{
//	  cout<<1<<endl;
	  qclass=words[2];
	  qtype=words[3];
	  cpos=4;
	  // 1
	}
      else
	{
//	  cout<<4<<endl;

	  qtype=words[2];
	  cpos=3;
	  // 4
	}
    }
  else /* 2 || 3 || 5 */
    {
      if(!isClass(words[1]))
	{

	  qtype=words[1];
	  cpos=2;
//	  cout<<5<<endl;
	  // 5
	}
      else // 2 || 3
	{
	  qclass=words[1];
	  if(isNumber(words[2])) 
	    {
	      ttl=zoneNumber(words[2]);
	      qtype=words[3];
//	      cout<<2<<endl;
	      cpos=4;
	      // 2
	    }
	  else if(isType(words[2]))
	    {
	      qtype=words[2];
//	      cout<<4<<endl;
	      cpos=3;
	      // 4
	    }
	}
      
    }
  if(!cpos) {
    throw AhuException("Funky parse case on line  "+itoa(d_lineno));
  }

  if(qname=="@")
    qname=d_origin;
  else
    if(qname[qname.size()-1]!='.')
      qname+="."+d_origin;


//  cerr<<qname<<", "<<qclass<<", "<<qtype<<", "<<ttl<<", rest from field "<<cpos<<endl;
	  
  int left=words.size()-cpos;
  string content;

  if(qtype=="MX" && left==2) {
    int prio=atoi(words[cpos++].c_str());
    content=words[cpos];
    if(content=="@")
      content=d_origin;
    else
      if(content[content.size()-1]!='.')
	content+="."+d_origin;
    
    fillRec(qname, qtype, content, ttl, prio,rec);
    return true;
  }
  else if(left) {
    content=words[cpos++];left--;
    
    while(left--)
      content+=" "+words[cpos++];
    
    if(qtype=="MX" || qtype=="CNAME" || qtype=="NS") {
      if(content=="@")
	content=d_origin;
      else
	if(content[content.size()-1]!='.')
	  content+="."+d_origin;
    }
    if(qtype=="SOA")
      soaCanonic(content);
    
    fillRec(qname, qtype, content,ttl, 0, rec);
    return true;
  }
  else {
    throw AhuException("No content on line  "+itoa(d_lineno));
  }
  return false;
}


