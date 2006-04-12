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
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef PDNS_ZONEPARSER_TNG
#define PDNS_ZONEPARSER_TNG
#include <string>
#include <cstdio>
using namespace std;

// The API is fine, the implementation still sucks
class ZoneParserTNG
{
public:
  ZoneParserTNG(const string& fname);

  ~ZoneParserTNG();

  bool get(DNSResourceRecord& rr);

private:
  FILE *d_fp;
  string d_line;
  bool getLine();
};

#endif
