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
#include "dnsdist-dynbpf.hh"

bool DynBPFFilter::block(const ComboAddress& addr, const struct timespec& until)
{
  bool inserted = false;
  auto data = d_data.lock();

  if (data->d_excludedSubnets.match(addr)) {
    /* do not add a block for excluded subnets */
    return inserted;
  }

  const container_t::iterator it = data->d_entries.find(addr);
  if (it != data->d_entries.end()) {
    if (it->d_until < until) {
      data->d_entries.replace(it, BlockEntry(addr, until));
    }
  }
  else {
    data->d_bpf->block(addr, BPFFilter::MatchAction::Drop);
    data->d_entries.insert(BlockEntry(addr, until));
    inserted = true;
  }
  return inserted;
}

void DynBPFFilter::purgeExpired(const struct timespec& now)
{
  auto data = d_data.lock();

  typedef boost::multi_index::nth_index<container_t,1>::type ordered_until;
  ordered_until& ou = boost::multi_index::get<1>(data->d_entries);

  for (ordered_until::iterator it = ou.begin(); it != ou.end(); ) {
    if (it->d_until < now) {
      ComboAddress addr = it->d_addr;
      it = ou.erase(it);
      data->d_bpf->unblock(addr);
    }
    else {
      break;
    }
  }
}

std::vector<std::tuple<ComboAddress, uint64_t, struct timespec> > DynBPFFilter::getAddrStats()
{
  std::vector<std::tuple<ComboAddress, uint64_t, struct timespec> > result;
  auto data = d_data.lock();

  if (!data->d_bpf) {
    return result;
  }

  const auto& stats = data->d_bpf->getAddrStats();
  result.reserve(stats.size());
  for (const auto& stat : stats) {
    const container_t::iterator it = data->d_entries.find(stat.first);
    if (it != data->d_entries.end()) {
      result.emplace_back(stat.first, stat.second, it->d_until);
    }
  }
  return result;
}
