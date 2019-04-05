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
#include "dnsname.hh"
#include <deque>
#include <map>
#include "iputils.hh"

class StatNode
{
public:

  struct Stat
  {
    Stat() : queries(0), noerrors(0), nxdomains(0), servfails(0), drops(0){}
    uint64_t queries, noerrors, nxdomains, servfails, drops;

    Stat& operator+=(const Stat& rhs) {
      queries+=rhs.queries;
      noerrors+=rhs.noerrors;
      nxdomains+=rhs.nxdomains;
      servfails+=rhs.servfails;
      drops+=rhs.drops;

      for(const remotes_t::value_type& rem : rhs.remotes) {
        remotes[rem.first]+=rem.second;
      }
      return *this;
    }
    typedef std::map<ComboAddress,int,ComboAddress::addressOnlyLessThan> remotes_t;
    remotes_t remotes;
  };

  Stat s;
  std::string name;
  std::string fullname;
  unsigned int labelsCount{0};

  void submit(const DNSName& domain, int rcode, boost::optional<const ComboAddress&> remote);

  Stat print(unsigned int depth=0, Stat newstat=Stat(), bool silent=false) const;
  typedef boost::function<void(const StatNode*, const Stat& selfstat, const Stat& childstat)> visitor_t;
  void visit(visitor_t visitor, Stat& newstat, unsigned int depth=0) const;
  bool empty() const
  {
    return children.empty() && s.remotes.empty();
  }
  typedef std::map<std::string,StatNode, CIStringCompare> children_t;
  children_t children;

private:
  void submit(std::vector<string>::const_iterator end, std::vector<string>::const_iterator begin, const std::string& domain, int rcode, boost::optional<const ComboAddress&> remote, unsigned int count);
};
