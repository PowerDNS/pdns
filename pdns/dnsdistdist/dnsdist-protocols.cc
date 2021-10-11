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

#include <algorithm>

#include "dnsdist-protocols.hh"

namespace dnsdist
{
static const std::vector<std::string> names = {
  "DoUDP",
  "DoTCP",
  "DNSCryptUDP",
  "DNSCryptTCP",
  "DoT",
  "DoH"};

static const std::vector<std::string> prettyNames = {
  "Do53 UDP",
  "Do53 TCP",
  "DNSCrypt UDP",
  "DNSCrypt TCP",
  "DNS over TLS",
  "DNS over HTTPS"};

Protocol::Protocol(uint8_t protocol) :
  d_protocol(protocol)
{
}
Protocol& Protocol::operator=(const char* s)
{
  std::string str(s);
  d_protocol = Protocol::fromString(str);

  return *this;
}
Protocol& Protocol::operator=(const std::string& s)
{
  d_protocol = Protocol::fromString(s);

  return *this;
}
Protocol::operator uint8_t() const
{
  return d_protocol;
}
const std::string& Protocol::toString() const
{
  return names.at(static_cast<int>(d_protocol));
}
const std::string& Protocol::toPrettyString() const
{
  return prettyNames.at(static_cast<int>(d_protocol));
}
uint8_t Protocol::fromString(const std::string& s)
{
  const auto& it = std::find(names.begin(), names.end(), s);
  if (it != names.end()) {
    return std::distance(names.begin(), it);
  }

  return 0;
}
}
