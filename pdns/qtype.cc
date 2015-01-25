/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2007 PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

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
#include "lock.hh"

vector<QType::namenum> QType::names;
// XXX FIXME we need to do something with initializer order here!
QType::init QType::initializer; 

QType::QType()
{
}

bool QType::isSupportedType() {
  for(vector<namenum>::iterator pos=names.begin();pos<names.end();++pos)
    if(pos->second==code)
      return true;
  return false;
}

bool QType::isMetadataType() {
  if (code == QType::AXFR ||
      code == QType::MAILA ||
      code == QType::MAILB ||
      code == QType::TSIG ||
      code == QType::IXFR)
    return true;

  return false;
}

uint16_t QType::getCode() const
{
  return code;
}

const string QType::getName() const
{
  vector<namenum>::iterator pos;
  for(pos=names.begin();pos<names.end();++pos)
    if(pos->second==code)
      return pos->first;

  return "TYPE"+itoa(code);
}

QType &QType::operator=(uint16_t n)
{
  code=n;
  return *this;
}

int QType::chartocode(const char *p)
{
  string P = toUpper(p);
  vector<namenum>::iterator pos;

  for(pos=names.begin(); pos < names.end(); ++pos)
    if(pos->first == P)
      return pos->second;

  if(*p=='#') {
    return atoi(p+1);
  }

  if(boost::starts_with(P, "TYPE"))
    return atoi(p+4);

  return 0;
}

QType &QType::operator=(const char *p)
{
  code=chartocode(p);
  return *this;
}

QType &QType::operator=(const string &s)
{
  code=chartocode(s.c_str());
  return *this;
}


QType::QType(uint16_t n)
{
  QType();
  code=n;
}
