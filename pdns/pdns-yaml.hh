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
#include <yaml-cpp/yaml.h>
#include "iputils.hh"
#include "dnsname.hh"

// Allows reading/writing ComboAddresses and DNSNames in YAML-cpp
namespace YAML {
template<>
struct convert<ComboAddress> {
  static Node encode(const ComboAddress& rhs) {
    return Node(rhs.toStringWithPortExcept(53));
  }
  static bool decode(const Node& node, ComboAddress& rhs) {
    if (!node.IsScalar()) {
      return false;
    }
    try {
      rhs = ComboAddress(node.as<string>(), 53);
      return true;
    } catch(const runtime_error &e) {
      return false;
    } catch (const PDNSException &e) {
      return false;
    }
  }
};

template<>
struct convert<DNSName> {
  static Node encode(const DNSName& rhs) {
    return Node(rhs.toStringRootDot());
  }
  static bool decode(const Node& node, DNSName& rhs) {
    if (!node.IsScalar()) {
      return false;
    }
    try {
      rhs = DNSName(node.as<string>());
      return true;
    } catch(const std::exception &e) {
      return false;
    } catch (const PDNSException &e) {
      return false;
    }
  }
};

template<>
struct convert<Netmask> {
  static Node encode(const Netmask& rhs) {
    return Node(rhs.toString());
  }
  static bool decode(const Node& node, Netmask& rhs) {
    if (!node.IsScalar()) {
      return false;
    }
    try {
      rhs = Netmask(node.as<string>());
      return true;
    } catch(const std::exception &e) {
      return false;
    } catch (const PDNSException &e) {
      return false;
    }
  }
};

template<>
struct convert<NetmaskGroup> {
  static Node encode(const NetmaskGroup& rhs) {
    vector<string> entries;
    rhs.toStringVector(&entries);
    return Node(entries);
  }
  static bool decode(const Node& node, NetmaskGroup& rhs)
  {
    if (!node.IsSequence()) {
      return false;
    }
    try {
      auto entries = node.as<vector<string>>();
      for (auto const &entry : entries) {
        rhs.addMask(entry);
      }
      return true;
    } catch(const std::exception &e) {
      return false;
    } catch (const PDNSException &e) {
      return false;
    }
  }
};
} // namespace YAML