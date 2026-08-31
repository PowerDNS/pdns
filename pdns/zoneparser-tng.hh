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
#include <stack>
#include <vector>

#include "dns.hh"
#include "dnsname.hh"

class ZoneParserTNG
{
public:
  ZoneParserTNG(const ZoneParserTNG&) = default;
  ZoneParserTNG(ZoneParserTNG&&) = delete;
  ZoneParserTNG& operator=(const ZoneParserTNG&) = default;
  ZoneParserTNG& operator=(ZoneParserTNG&&) = delete;
  ZoneParserTNG(const std::string& fname, ZoneName zname = g_rootzonename, std::string reldir = "", bool upgradeContent = false);
  ZoneParserTNG(const std::vector<std::string>& zonedata, ZoneName zname, bool upgradeContent = false);

  ~ZoneParserTNG();
  bool get(DNSResourceRecord& dnsrr, std::string* comment = nullptr);
  using exception = std::runtime_error;
  using parts_t = std::deque<std::pair<std::string::size_type, std::string::size_type>>;
  ZoneName getZoneName();
  std::string getLineOfFile(); // for error reporting purposes
  std::pair<std::string, int> getLineNumAndFile(); // idem
  void disableGenerate()
  {
    d_generateEnabled = false;
  }
  void setMaxGenerateSteps(size_t max)
  {
    d_maxGenerateSteps = max;
  }
  void setMaxIncludes(size_t max)
  {
    d_maxIncludes = max;
  }
  void setDefaultTTL(int ttl)
  {
    d_defaultttl = ttl;
    d_havespecificttl = true;
  }
  [[nodiscard]] std::vector<std::pair<std::string, time_t>> getFileset() const { return d_fileset; }

private:
  bool getLine();
  bool getTemplateLine();
  void stackFile(const std::string& fname);
  unsigned makeTTLFromZone(const std::string& str);

  struct filestate
  {
    filestate(FILE* filePtr, std::string filename) :
      d_fp(filePtr), d_filename(std::move(filename)) {}
    FILE* d_fp;
    std::string d_filename;
    int d_lineno{0};
  };

  parts_t d_parts;
  std::string d_reldir;
  std::string d_line;
  DNSName d_prevqname;
  ZoneName d_zonename;
  std::string d_templateline;
  std::vector<std::string> d_zonedata;
  std::vector<std::string>::iterator d_zonedataline;
  std::stack<filestate> d_filestates;
  parts_t d_templateparts;
  size_t d_maxGenerateSteps{0};
  size_t d_maxIncludes{20};
  uint32_t d_defaultttl;
  uint32_t d_templatecounter, d_templatestop, d_templatestep;
  bool d_havespecificttl;
  bool d_fromfile;
  bool d_generateEnabled{true};
  bool d_upgradeContent;
  bool d_templateCounterWrapped{false};
  std::vector<std::pair<std::string, time_t>> d_fileset;
};
