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
#include <stdexcept>
#include <iostream>
#include <boost/algorithm/string.hpp>
#include <boost/assign/list_of.hpp>
#include "dnsparser.hh"

std::vector<std::string> RCode::rcodes_s = boost::assign::list_of 
  ("No Error")
  ("Form Error")
  ("Server Failure")
  ("Non-Existent domain")
  ("Not Implemented")
  ("Query Refused")
  ("Name Exists when it should not")
  ("RR Set Exists when it should not")
  ("RR Set that should exist does not")
  ("Server Not Authoritative for zone / Not Authorized")
  ("Name not contained in zone")
  ("Err#11")
  ("Err#12")
  ("Err#13")
  ("Err#14")
  ("Err#15")  // Last non-extended RCode
  ("Bad OPT Version / TSIG Signature Failure")
  ("Key not recognized")
  ("Signature out of time window")
  ("Bad TKEY Mode")
  ("Duplicate key name")
  ("Algorithm not supported")
  ("Bad Truncation")
  ("Bad/missing Server Cookie")
;

std::string RCode::to_s(uint8_t rcode) {
  if (rcode > 0xF)
    return std::string("ErrOutOfRange");
  return ERCode::to_s(rcode);
}

std::string ERCode::to_s(uint8_t rcode) {
  if (rcode > RCode::rcodes_s.size()-1)
    return std::string("Err#")+std::to_string(rcode);
  return RCode::rcodes_s[rcode];
}

std::string Opcode::to_s(uint8_t opcode) {
  static const std::vector<std::string> s_opcodes = { "Query", "IQuery", "Status", "3", "Notify", "Update" };

  if (opcode >= s_opcodes.size()) {
    return std::to_string(opcode);
  }

  return s_opcodes.at(opcode);
}

// goal is to hash based purely on the question name, and turn error into 'default'
uint32_t hashQuestion(const uint8_t* packet, uint16_t packet_len, uint32_t init)
{
  if (packet_len < sizeof(dnsheader)) {
    return init;
  }
  // C++ 17 does not have std::u8string_view
  std::basic_string_view<uint8_t> name(packet + sizeof(dnsheader), packet_len - sizeof(dnsheader));
  std::basic_string_view<uint8_t>::size_type len = 0;

  while (len < name.length()) {
    uint8_t labellen = name[len++];
    if (labellen == 0) {
      // len is name.length() at max as it was < before the increment
      return burtleCI(name.data(), len, init);
    }
    len += labellen;
  }
  // We've encountered a label that is too long
  return init;
}

