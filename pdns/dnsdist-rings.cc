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

#include "dnsdist-rings.hh"

size_t Rings::numDistinctRequestors()
{
  std::set<ComboAddress, ComboAddress::addressOnlyLessThan> s;
  for (const auto& shard : d_shards) {
    std::lock_guard<std::mutex> rl(shard->queryLock);
    for(const auto& q : shard->queryRing) {
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
      std::lock_guard<std::mutex> rl(shard->queryLock);
      for(const auto& q : shard->queryRing) {
        counts[q.requestor]+=q.size;
        total+=q.size;
      }
    }
    {
      std::lock_guard<std::mutex> rl(shard->respLock);
      for(const auto& r : shard->respRing) {
        counts[r.requestor]+=r.size;
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
  ret.insert({count, {"Rest", rest, total > 0 ? 100.0*rest/total : 100.0}});
  return ret;
}
