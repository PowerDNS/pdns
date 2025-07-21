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

#include "dnsdist-mac-address.hh"
#include "misc.hh"

namespace dnsdist
{
SharedLockGuarded<boost::circular_buffer<MacAddressesCache::Entry>> MacAddressesCache::s_cache;

int MacAddressesCache::get(const ComboAddress& ca, unsigned char* dest, size_t destLen)
{
  if (dest == nullptr || destLen < sizeof(Entry::mac)) {
    return EINVAL;
  }

  auto compare = ComboAddress::addressOnlyEqual();
  time_t now = time(nullptr);

  {
    auto cache = s_cache.read_lock();
    for (const auto& entry : *cache) {
      if (entry.ttd >= now && compare(entry.ca, ca) == true) {
        if (!entry.found) {
          // negative entry
          return ENOENT;
        }
        memcpy(dest, entry.mac.data(), entry.mac.size());
        return 0;
      }
    }
  }

  auto res = getMACAddress(ca, reinterpret_cast<char*>(dest), destLen);
  Entry entry;
  entry.ca = ca;
  if (res == 0) {
    memcpy(entry.mac.data(), dest, entry.mac.size());
    entry.found = true;
  }
  else {
    memset(entry.mac.data(), 0, entry.mac.size());
    entry.found = false;
  }
  entry.ttd = now + MacAddressesCache::s_cacheValiditySeconds;
  {
    auto cache = s_cache.write_lock();
    if (cache->capacity() == 0) {
      cache->set_capacity(MacAddressesCache::s_cacheSize);
    }
    cache->push_back(std::move(entry));
  }

  return res;
}
}
