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
#include <stdexcept>

#include "dnsdist-protocols.hh"

namespace dnsdist
{
const std::array<std::string, Protocol::s_numberOfProtocols> Protocol::s_names = {
  "DoUDP",
  "DoTCP",
  "DNSCryptUDP",
  "DNSCryptTCP",
  "DoT",
  "DoH",
  "DoQ",
  "DoH3"};

const std::array<std::string, Protocol::s_numberOfProtocols> Protocol::s_prettyNames = {
  "Do53 UDP",
  "Do53 TCP",
  "DNSCrypt UDP",
  "DNSCrypt TCP",
  "DNS over TLS",
  "DNS over HTTPS",
  "DNS over QUIC",
  "DNS over HTTP/3"};

Protocol::Protocol(const std::string& protocol)
{
  const auto& namesIt = std::find(s_names.begin(), s_names.end(), protocol);
  if (namesIt == s_names.end()) {
    throw std::runtime_error("Unknown protocol name: '" + protocol + "'");
  }

  auto index = std::distance(s_names.begin(), namesIt);
  d_protocol = static_cast<Protocol::typeenum>(index);
}

bool Protocol::operator==(Protocol::typeenum type) const
{
  return d_protocol == type;
}

bool Protocol::operator!=(Protocol::typeenum type) const
{
  return d_protocol != type;
}

bool Protocol::operator==(const Protocol& rhs) const
{
  return d_protocol == rhs.d_protocol;
}

bool Protocol::operator!=(const Protocol& rhs) const
{
  return d_protocol != rhs.d_protocol;
}

const std::string& Protocol::toString() const
{
  return s_names.at(static_cast<uint8_t>(d_protocol));
}

const std::string& Protocol::toPrettyString() const
{
  return s_prettyNames.at(static_cast<uint8_t>(d_protocol));
}

bool Protocol::isUDP() const
{
  return d_protocol == DoUDP || d_protocol == DNSCryptUDP;
}

bool Protocol::isEncrypted() const
{
  return d_protocol != DoUDP && d_protocol != DoTCP;
}

uint8_t Protocol::toNumber() const
{
  return static_cast<uint8_t>(d_protocol);
}
}
