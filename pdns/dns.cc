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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dns.hh"
#include "misc.hh"
#include "views.hh"
#include <stdexcept>
#include <iostream>
#include <boost/algorithm/string.hpp>
#include <boost/assign/list_of.hpp>
#include "dnsparser.hh"

const std::array<std::string, 24> RCode::rcodes_s = {
  "No Error",
  "Form Error",
  "Server Failure",
  "Non-Existent domain",
  "Not Implemented",
  "Query Refused",
  "Name Exists when it should not",
  "RR Set Exists when it should not",
  "RR Set that should exist does not",
  "Server Not Authoritative for zone / Not Authorized",
  "Name not contained in zone",
  "Err#11",
  "Err#12",
  "Err#13",
  "Err#14",
  "Err#15",  // Last non-extended RCode
  "Bad OPT Version / TSIG Signature Failure",
  "Key not recognized",
  "Signature out of time window",
  "Bad TKEY Mode",
  "Duplicate key name",
  "Algorithm not supported",
  "Bad Truncation",
  "Bad/missing Server Cookie"
};

static const std::array<std::string, 24> rcodes_short_s =  {
  "noerror",
  "formerr",
  "servfail",
  "nxdomain",
  "notimp",
  "refused",
  "yxdomain",
  "yxrrset",
  "nxrrset",
  "notauth",
  "notzone",
  "rcode11",
  "rcode12",
  "rcode13",
  "rcode14",
  "rcode15",
  "badvers",
  "badkey",
  "badtime",
  "badmode",
  "badname",
  "badalg",
  "badtrunc",
  "badcookie",
};

std::string RCode::to_s(uint8_t rcode) {
  if (rcode > 0xF) {
    return "ErrOutOfRange";
  }
  return ERCode::to_s(rcode);
}

std::string RCode::to_short_s(uint8_t rcode) {
  if (rcode > 0xF) {
    return "ErrOutOfRange";
  }
  return ERCode::to_short_s(rcode);
}

std::optional<uint8_t> RCode::from_short(const std::string_view& rcode_string)
{
  const auto* position = std::find(rcodes_short_s.begin(), rcodes_short_s.end(), rcode_string);
  if (position == rcodes_short_s.end()) {
    return std::nullopt;
  }
  auto code = std::distance(rcodes_short_s.begin(), position);
  if (code > 0xF) {
    return std::nullopt;
  }
  return code;
}

std::string ERCode::to_s(uint16_t rcode) {
  if (rcode >= RCode::rcodes_s.size()) {
    return std::string("Err#") + std::to_string(rcode);
  }
  return RCode::rcodes_s.at(rcode);
}

std::string ERCode::to_short_s(uint16_t rcode) {
  if (rcode >= rcodes_short_s.size()) {
    return "rcode" + std::to_string(rcode);
  }
  return rcodes_short_s.at(rcode);
}

std::optional<uint16_t> ERCode::from_short(const std::string_view& ercode_string)
{
  const auto* position = std::find(rcodes_short_s.begin(), rcodes_short_s.end(), ercode_string);
  if (position == rcodes_short_s.end()) {
    return std::nullopt;
  }
  return std::distance(rcodes_short_s.begin(), position);
}

std::string Opcode::to_s(uint8_t opcode) {
  static const std::array<std::string, 6> s_opcodes = { "Query", "IQuery", "Status", "3", "Notify", "Update" };

  if (opcode >= s_opcodes.size()) {
    return std::to_string(opcode);
  }

  return s_opcodes.at(opcode);
}

// goal is to hash based purely on the question name, and turn error into 'default'
uint32_t hashQuestion(const uint8_t* packet, uint16_t packet_len, uint32_t init, bool& wasOK)
{
  if (packet_len < sizeof(dnsheader)) {
    wasOK = false;
    return init;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  pdns::views::UnsignedCharView name(packet + sizeof(dnsheader), packet_len - sizeof(dnsheader));
  pdns::views::UnsignedCharView::size_type len = 0;

  while (len < name.length()) {
    uint8_t labellen = name[len++];
    if (labellen == 0) {
      wasOK = true;
      // len is name.length() at max as it was < before the increment
      return burtleCI(name.data(), len, init);
    }
    len += labellen;
  }
  // We've encountered a label that is too long
  wasOK = false;
  return init;
}

static const std::array<std::string, 4> placeNames = {
  "QUESTION",
  "ANSWER",
  "AUTHORITY",
  "ADDITIONAL"
};

std::string DNSResourceRecord::placeString(uint8_t place)
{
  if (place >= placeNames.size()) {
    return "?";
  }
  return placeNames.at(place);
}
