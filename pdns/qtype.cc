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
#include "utility.hh"
#include <iostream>
#include <string>
#include <vector>
#include <utility>
#include <sstream>
#include "qtype.hh"
#include "misc.hh"

bool QType::uninit=true;
vector<QType::namenum> QType::names;

void QType::insert(char *p, int n)
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
      insert("PTR",12);
      insert("HINFO",13);
      insert("MX",15);
      insert("TXT",16);
      insert("RP",17);
      insert("SRV",33);
      insert("A6",38);
      insert("AAAA",28);
      insert("NAPTR",35);
      insert("AXFR",252);
      insert("ANY",255);
      insert("URL",256);
      insert("MBOXFW",257);
      insert("CURL",258);
    }
}

int QType::getCode() const
{
  return code;
}

string QType::getName() const
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

QType::QType(char *p)
{
  QType();
  code=chartocode(p);
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
