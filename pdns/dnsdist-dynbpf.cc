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

#ifdef HAVE_EBPF

void DynBPFFilter::block(const ComboAddress& addr, const struct timespec& until)
{
  std::unique_lock<std::mutex> lock(d_mutex);

  const container_t::iterator it = d_entries.find(addr);
  if (it != d_entries.end()) {
    if (it->d_until < until) {
      d_entries.replace(it, BlockEntry(addr, until));
    }
  }
  else {
    d_bpf->block(addr);
    d_entries.insert(BlockEntry(addr, until));
  }
}

void DynBPFFilter::purgeExpired(const struct timespec& now)
{
  std::unique_lock<std::mutex> lock(d_mutex);

  typedef nth_index<container_t,1>::type ordered_until;
  ordered_until& ou = get<1>(d_entries);

  for (ordered_until::iterator it=ou.begin(); it != ou.end(); ) {
    if (it->d_until < now) {
      ComboAddress addr = it->d_addr;
      it = ou.erase(it);
      d_bpf->unblock(addr);
    }
    else {
      break;
    }
  }
}

#endif /* HAVE_EBPF */
