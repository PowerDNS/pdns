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

#include "circular_buffer.hh"
#include "iputils.hh"
#include "lock.hh"

namespace dnsdist
{
using MacAddress = std::array<uint8_t, 6>;

class MacAddressesCache
{
public:
  static int get(const ComboAddress& ca, unsigned char* dest, size_t len);

private:
  struct Entry
  {
    ComboAddress ca;
    MacAddress mac;
    time_t ttd;
    bool found;
  };

  static constexpr size_t s_cacheSize{10};
  static constexpr time_t s_cacheValiditySeconds{60};
  static SharedLockGuarded<boost::circular_buffer<Entry>> s_cache;
};
}
