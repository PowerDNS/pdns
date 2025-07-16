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
#include "dnsdist-actions.hh"

#include <boost/algorithm/string.hpp>

DNSAction::Action DNSAction::typeFromString(const std::string& str)
{
  static const std::unordered_map<std::string, Action> s_mappings{
    {"allow", Action::Allow},
    {"delay", Action::Delay},
    {"drop", Action::Drop},
    {"headermodify", Action::HeaderModify},
    {"none", Action::None},
    {"noop", Action::NoOp},
    {"norecurse", Action::NoRecurse},
    {"nxdomain", Action::Nxdomain},
    {"pool", Action::Pool},
    {"refused", Action::Refused},
    {"servfail", Action::ServFail},
    {"settag", Action::SetTag},
    {"spoof", Action::Spoof},
    {"spoofpacket", Action::SpoofPacket},
    {"spoofraw", Action::SpoofRaw},
    {"truncate", Action::Truncate},
  };

  auto lower = boost::to_lower_copy(str);
  lower.erase(std::remove(lower.begin(), lower.end(), '-'), lower.end());
  auto mappingIt = s_mappings.find(lower);
  if (mappingIt != s_mappings.end()) {
    return mappingIt->second;
  }
  throw std::runtime_error("Unable to convert '" + str + "' into a DNS Action");
}

std::string DNSAction::typeToString(DNSAction::Action action)
{
  switch (action) {
  case Action::Drop:
    return "Drop";
  case Action::Nxdomain:
    return "Send NXDomain";
  case Action::Refused:
    return "Send Refused";
  case Action::Spoof:
    return "Spoof an answer";
  case Action::SpoofPacket:
    return "Spoof a raw answer from bytes";
  case Action::SpoofRaw:
    return "Spoof an answer from raw bytes";
  case Action::Allow:
    return "Allow";
  case Action::HeaderModify:
    return "Modify the header";
  case Action::Pool:
    return "Route to a pool";
  case Action::Delay:
    return "Delay";
  case Action::Truncate:
    return "Truncate over UDP";
  case Action::ServFail:
    return "Send ServFail";
  case Action::SetTag:
    return "Set Tag";
  case Action::None:
  case Action::NoOp:
    return "Do nothing";
  case Action::NoRecurse:
    return "Set rd=0";
  }

  return "Unknown";
}
