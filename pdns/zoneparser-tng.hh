/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2005 - 2007 PowerDNS.COM BV

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
#include <stdexcept>
#include <stack>

using namespace std;

class ZoneParserTNG
{
public:
  ZoneParserTNG(const string& fname, const string& zname="", const string& reldir="");

  ~ZoneParserTNG();

  bool get(DNSResourceRecord& rr);
  typedef runtime_error exception;
  typedef deque<pair<string::size_type, string::size_type> > parts_t;
private:
  bool getLine();
  bool getTemplateLine();
  void stackFile(const std::string& fname);
  stack<FILE *> d_fps;
  string d_reldir;
  string d_line;
  string d_prevqname;
  string d_zonename;
  int d_defaultttl;
  uint32_t d_templatecounter, d_templatestop, d_templatestep;
  string d_templateline;
  parts_t d_templateparts;
};

#endif
