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

#include <vector>
#include <string>

namespace dnsdist
{
class Protocol
{
public:
  Protocol(uint8_t protocol = 0);
  Protocol& operator=(const char*);
  Protocol& operator=(const std::string&);
  operator uint8_t() const;
  const std::string& toString() const;
  const std::string& toPrettyString() const;

  enum typeenum : uint8_t
  {
    DoUDP,
    DoTCP,
    DNSCryptUDP,
    DNSCryptTCP,
    DoT,
    DoH
  };

private:
  static uint8_t fromString(const std::string& s);
  uint8_t d_protocol;
};
}
