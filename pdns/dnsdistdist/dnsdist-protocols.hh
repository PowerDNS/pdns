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

#include <array>
#include <cstdint>
#include <string>

namespace dnsdist
{
class Protocol
{
public:
  enum typeenum : uint8_t
  {
    DoUDP = 0,
    DoTCP,
    DNSCryptUDP,
    DNSCryptTCP,
    DoT,
    DoH,
    DoQ,
    DoH3
  };

  Protocol(typeenum protocol = DoUDP) :
    d_protocol(protocol)
  {
    if (protocol >= s_names.size()) {
      throw std::runtime_error("Unknown protocol: '" + std::to_string(protocol) + "'");
    }
  }

  explicit Protocol(const std::string& protocol);

  bool operator==(typeenum) const;
  bool operator!=(typeenum) const;
  bool operator==(const Protocol& rhs) const;
  bool operator!=(const Protocol& rhs) const;

  const std::string& toString() const;
  const std::string& toPrettyString() const;
  bool isUDP() const;
  bool isEncrypted() const;
  uint8_t toNumber() const;

private:
  typeenum d_protocol;

  static constexpr size_t s_numberOfProtocols = 8;
  static const std::array<std::string, s_numberOfProtocols> s_names;
  static const std::array<std::string, s_numberOfProtocols> s_prettyNames;
};
}
