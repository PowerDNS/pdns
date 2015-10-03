/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2005 - 2007 PowerDNS.COM BV

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

#ifndef PDNS_ZONEPARSER_TNG
#define PDNS_ZONEPARSER_TNG
#include <string>
#include <cstdio>
#include <stdexcept>
#include <stack>

#include "namespaces.hh"

class ZoneParserTNG
{
public:
  ZoneParserTNG(const string& fname, const DNSName& zname=DNSName(), const string& reldir="");
  ZoneParserTNG(const vector<string> zonedata, const DNSName& zname);

  ~ZoneParserTNG();
  bool get(DNSResourceRecord& rr, std::string* comment=0);
  typedef runtime_error exception;
  typedef deque<pair<string::size_type, string::size_type> > parts_t;
private:
  bool getLine();
  bool getTemplateLine();
  void stackFile(const std::string& fname);
  unsigned makeTTLFromZone(const std::string& str);
  string getLineOfFile();
  struct filestate {
    filestate(FILE* fp, string filename) : d_fp(fp), d_filename(filename), d_lineno(0){}
    FILE *d_fp;
    string d_filename;
    int d_lineno;
  };

  string d_reldir;
  string d_line;
  DNSName d_prevqname;
  DNSName d_zonename;
  string d_templateline;
  vector<string> d_zonedata;
  vector<string>::iterator d_zonedataline;
  std::stack<filestate> d_filestates;
  parts_t d_templateparts;
  int d_defaultttl;
  uint32_t d_templatecounter, d_templatestop, d_templatestep;
  bool d_havedollarttl;
  bool d_fromfile;
};

#endif
