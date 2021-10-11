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

#include <fstream>

#include "dnsdist-rings.hh"

size_t Rings::numDistinctRequestors()
{
  std::set<ComboAddress, ComboAddress::addressOnlyLessThan> s;
  for (const auto& shard : d_shards) {
    auto rl = shard->queryRing.lock();
    for (const auto& q : *rl) {
      s.insert(q.requestor);
    }
  }
  return s.size();
}

std::unordered_map<int, vector<boost::variant<string,double>>> Rings::getTopBandwidth(unsigned int numentries)
{
  map<ComboAddress, unsigned int, ComboAddress::addressOnlyLessThan> counts;
  uint64_t total=0;
  for (const auto& shard : d_shards) {
    {
      auto rl = shard->queryRing.lock();
      for(const auto& q : *rl) {
        counts[q.requestor] += q.size;
        total+=q.size;
      }
    }
    {
      auto rl = shard->respRing.lock();
      for(const auto& r : *rl) {
        counts[r.requestor] += r.size;
        total+=r.size;
      }
    }
  }

  typedef vector<pair<unsigned int, ComboAddress>> ret_t;
  ret_t rcounts;
  rcounts.reserve(counts.size());
  for(const auto& p : counts)
    rcounts.push_back({p.second, p.first});
  numentries = rcounts.size() < numentries ? rcounts.size() : numentries;
  partial_sort(rcounts.begin(), rcounts.begin()+numentries, rcounts.end(), [](const ret_t::value_type&a, const ret_t::value_type&b)
	       {
		 return(b.first < a.first);
	       });
  std::unordered_map<int, vector<boost::variant<string,double>>> ret;
  uint64_t rest = 0;
  unsigned int count = 1;
  for(const auto& rc : rcounts) {
    if(count==numentries+1) {
      rest+=rc.first;
    }
    else {
      ret.insert({count++, {rc.second.toString(), rc.first, 100.0*rc.first/total}});
    }
  }

  if (total > 0) {
    ret.insert({count, {"Rest", rest, 100.0*rest/total}});
  }
  else {
    ret.insert({count, {"Rest", rest, 100.0 }});
  }

  return ret;
}

size_t Rings::loadFromFile(const std::string& filepath, const struct timespec& now)
{
  ifstream ifs(filepath);
  if (!ifs) {
    throw std::runtime_error("unable to open the file at " + filepath);
  }

  size_t inserted = 0;
  string line;
  dnsheader dh;
  memset(&dh, 0, sizeof(dh));

  while (std::getline(ifs, line)) {
    boost::trim_right_if(line, boost::is_any_of(" \r\n\x1a"));
    boost::trim_left(line);
    bool isResponse = false;
    vector<string> parts;
    stringtok(parts, line, " \t,");

    if (parts.size() == 8) {
    }
    else if (parts.size() >= 11 && parts.size() <= 13) {
      isResponse = true;
    }
    else {
      cerr<<"skipping line with "<<parts.size()<<"parts: "<<line<<endl;
      continue;
    }

    size_t idx = 0;
    vector<string> timeStr;
    stringtok(timeStr, parts.at(idx++), ".");
    if (timeStr.size() != 2) {
      cerr<<"skipping invalid time "<<parts.at(0)<<endl;
      continue;
    }

    struct timespec when;
    try {
      when.tv_sec = now.tv_sec + std::stoi(timeStr.at(0));
      when.tv_nsec = now.tv_nsec + std::stoi(timeStr.at(1)) * 100 * 1000 * 1000;
    }
    catch (const std::exception& e) {
      cerr<<"error parsing time "<<parts.at(idx-1)<<" from line "<<line<<endl;
      continue;
    }

    ComboAddress from(parts.at(idx++));
    ComboAddress to;
    dnsdist::Protocol protocol(parts.at(idx++));
    if (isResponse) {
      to = ComboAddress(parts.at(idx++));
    }
    /* skip ID */
    idx++;
    DNSName qname(parts.at(idx++));
    QType qtype(QType::chartocode(parts.at(idx++).c_str()));

    if (isResponse) {
      insertResponse(when, from, qname, qtype.getCode(), 0, 0, dh, to, protocol);
    }
    else {
      insertQuery(when, from, qname, qtype.getCode(), 0, dh, protocol);
    }
    ++inserted;
  }

  return inserted;
}
