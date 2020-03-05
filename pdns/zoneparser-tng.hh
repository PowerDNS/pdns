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
#pragma once
#include <string>
#include <cstdio>
#include <stdexcept>
#include <stack>

#include "namespaces.hh"

class ZoneParserTNG
{
public:
  ZoneParserTNG(const string& fname, const DNSName& zname=g_rootdnsname, const string& reldir="");
  ZoneParserTNG(const vector<string> zonedata, const DNSName& zname);

  ~ZoneParserTNG();
  bool get(DNSResourceRecord& rr, std::string* comment=0);
  typedef runtime_error exception;
  typedef deque<pair<string::size_type, string::size_type> > parts_t;
  DNSName getZoneName();
  string getLineOfFile(); // for error reporting purposes
  pair<string,int> getLineNumAndFile(); // idem
  void disableGenerate()
  {
    d_generateEnabled = false;
  }
  void setMaxGenerateSteps(size_t max)
  {
    d_maxGenerateSteps = max;
  }
private:
  bool getLine();
  bool getTemplateLine();
  void stackFile(const std::string& fname);
  unsigned makeTTLFromZone(const std::string& str);

  struct filestate {
    filestate(FILE* fp, string filename) : d_fp(fp), d_filename(filename), d_lineno(0){}
    FILE *d_fp;
    string d_filename;
    int d_lineno;
  };

  parts_t d_parts;
  string d_reldir;
  string d_line;
  DNSName d_prevqname;
  DNSName d_zonename;
  string d_templateline;
  vector<string> d_zonedata;
  vector<string>::iterator d_zonedataline;
  std::stack<filestate> d_filestates;
  parts_t d_templateparts;
  size_t d_maxGenerateSteps{0};
  int d_defaultttl;
  uint32_t d_templatecounter, d_templatestop, d_templatestep;
  bool d_havedollarttl;
  bool d_fromfile;
  bool d_generateEnabled{true};
};
