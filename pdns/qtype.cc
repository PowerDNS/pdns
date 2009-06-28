/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2007 PowerDNS.COM BV

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
#include "utility.hh"
#include "dns.hh"
#include <iostream>
#include <string>
#include <vector>
#include <utility>
#include <sstream>
#include "qtype.hh"
#include "misc.hh"

bool QType::uninit=true;
vector<QType::namenum> QType::names;

void QType::insert(const char *p, int n)
{
  names.push_back(make_pair(string(p),n));
}


QType::QType()
{
  if(uninit)
    {
      uninit=false;
      insert("A",1);
      insert("NS",2);
      insert("CNAME",5);
      insert("SOA",6);
      insert("MR",9);
      insert("PTR",12);
      insert("HINFO",13);
      insert("MX",15);
      insert("TXT",16);
      insert("RP",17);
      insert("AFSDB", 18);
      insert("SIG",24);
      insert("KEY",25);
      insert("AAAA",28);
      insert("LOC",29);
      insert("SRV",33);
      insert("CERT", 37);
      insert("A6",38);
      insert("NAPTR",35);
      insert("DS", 43);
      insert("SSHFP", 44);
      insert("RRSIG", 46);
      insert("NSEC", 47);
      insert("DNSKEY", 48);
      insert("NSEC3", 50);
      insert("NSEC3PARAM", 51);
      insert("SPF",99);
      insert("IXFR",251);
      insert("AXFR",252);
      insert("ANY",255);
      insert("URL",256);
      insert("MBOXFW",257);
      insert("CURL",258);
      insert("ADDR",259);
    }
}

int QType::getCode() const
{
  return code;
}

const string QType::getName() const
{
  vector<namenum>::iterator pos;
  for(pos=names.begin();pos<names.end();++pos)
    if(pos->second==code)
      return pos->first;

  return "#"+itoa(code);
}

QType &QType::operator=(int n)
{
  code=n;
  return *this;
}

int QType::chartocode(const char *p)
{
  static QType qt;
  vector<namenum>::iterator pos;
  for(pos=names.begin();pos<names.end();++pos)
    if(pos->first==p)
      return pos->second;

  return 0;
}

QType &QType::operator=(const char *p)
{
  code=chartocode(p);
  return *this;
}

bool QType::operator==(const QType &comp) const
{
  return(comp.code==code);
}

QType &QType::operator=(const string &s)
{
  code=chartocode(s.c_str());
  return *this;
}


QType::QType(int n)
{
  QType();
  code=n;
}

QType::QType(const char *p)
{
  QType();
  code=chartocode(p);
}

string DNSResourceRecord::serialize() const
{
  ostringstream ostr;
  ostr<<escape(qname)<<"|"<<qtype.getName()<<"|"<<escape(content)<<"|"<<ttl<<"|"<<priority<<"|"<<domain_id
     <<"|"<<last_modified;
  return ostr.str();
}

string DNSResourceRecord::escape(const string &name) const
{
  string a;

  for(string::const_iterator i=name.begin();i!=name.end();++i)
    if(*i=='|' || *i=='\\'){
      a+='\\';
      a+=*i;
    }
    else
      a+=*i;

  return a;
}

int DNSResourceRecord::unSerialize(const string &source)
{
  // qname|qtype|content|ttl|priority|domain_id|last_modified;
  string chunk;
  unsigned int m=0;
  for(int n=0;n<7;++n) {
    chunk="";
    for(;m<source.size();++m) {
      if(source[m]=='\\' && m+1<source.size()) 
	chunk.append(1,source[++m]);
      else if(source[m]=='|') {
	++m;
	break;
      }
      else 
	chunk.append(1,source[m]);
    }
    switch(n) {
    case 0:
      qname=chunk;
      break;
    case 1:
      qtype=chunk;
      break;
    case 2:
      content=chunk;
      break;
    case 3:
      ttl=atoi(chunk.c_str());
      break;
    case 4:
      priority=atoi(chunk.c_str());
      break;
    case 5:
      domain_id=atoi(chunk.c_str());
      break;
    case 6:
      last_modified=atoi(chunk.c_str());
      break;
    }
  }
  return m;
}


#if 0
int main(int argc, char **argv)
{
  QType t;

  cout << endl;
  cout << "Assiging a '6'" << endl;
  t=6;
  cout << "Code is now " << t.getCode() << endl;
  cout << "Name is now " << t.getName() << endl;

  cout << endl;

  cout << "Assiging a 'CNAME'" << endl;
  t="CNAME";
  cout << "Code is now " << t.getCode() << endl;
  cout << "Name is now " << t.getName() << endl;

  QType u;
  u="SOA";
  cout << u.getCode() << endl;


}
#endif
