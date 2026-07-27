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

#include <net/if.h>

#include "query-local-address.hh"
#include "iputils.hh"
#include "dns_random.hh"
#include "logging.hh"
#include "logger.hh"

namespace pdns
{
  static const ComboAddress local4("0.0.0.0");
  static const ComboAddress local6("::");

  static vector<AddressAndInterface> g_localQueryAddresses4;
  static vector<AddressAndInterface> g_localQueryAddresses6;

  AddressAndInterface getQueryLocalAddress(const sa_family_t family, const in_port_t port) {
    AddressAndInterface ret;
    if (family==AF_INET) {
      if (g_localQueryAddresses4.empty()) {
        ret.d_address = local4;
      } else if (g_localQueryAddresses4.size() == 1) {
        ret = g_localQueryAddresses4.at(0);
      } else {
        ret = g_localQueryAddresses4[dns_random(g_localQueryAddresses4.size())];
      }
      ret.d_address.sin4.sin_port = htons(port);
    }
    else {
      if (g_localQueryAddresses6.empty()) {
        ret.d_address = local6;
      } else if (g_localQueryAddresses6.size() == 1) {
        ret = g_localQueryAddresses6.at(0);
      } else {
        ret = g_localQueryAddresses6[dns_random(g_localQueryAddresses6.size())];
      }
      ret.d_address.sin6.sin6_port = htons(port);
    }
    return ret;
  }

  AddressAndInterface getNonAnyQueryLocalAddress(const sa_family_t family) {
    if (family == AF_INET) {
      for (const auto& addr : pdns::g_localQueryAddresses4) {
        if (!IsAnyAddress(addr.d_address)) {
          return addr;
        }
      }
    }
    if (family == AF_INET6) {
      for (const auto& addr : pdns::g_localQueryAddresses6) {
        if (!IsAnyAddress(addr.d_address)) {
          return addr;
        }
      }
    }
    AddressAndInterface ret{ComboAddress{"0.0.0.0"}, std::nullopt};
    ret.d_address.reset(); // Ensure all is zero, even the addr family
    return ret;
  }

  void parseQueryLocalAddress(const std::string &qla) {
    std::vector<std::string> addrs;
    stringtok(addrs, qla, ", ;");
    for (const string& word : addrs) {
      vector<std::string> parts;
      std::string addr;
      std::optional<Interface> itf;
      stringtok(parts, word, "@");
      if (parts.empty()) {
        continue;
      }
      addr = parts.at(0);
      if (parts.size() >= 2) {
        auto idx = if_nametoindex(parts.at(1).data());
        if (idx == 0) {
          SLOG(g_log << Logger::Error << "Interface name " << parts.at(1) << " is unknown" << endl,
               g_slog->withName("runtime")->info(Logr::Error, "interface unknown", "name", Logging::Loggable(parts.at(1))));
        }
        itf = Interface{ parts.at(1), idx };
      }

      AddressAndInterface tmp{ComboAddress{addr}, std::move(itf)};
      if (tmp.d_address.isIPv4()) {
        g_localQueryAddresses4.emplace_back(std::move(tmp));
        continue;
      }
      g_localQueryAddresses6.emplace_back(std::move(tmp));
    }
  }

  bool isQueryLocalAddressFamilyEnabled(const sa_family_t family) {
    if (family == AF_INET) {
      return !g_localQueryAddresses4.empty();
    }
    if (family == AF_INET6) {
      return !g_localQueryAddresses6.empty();
    }
    return false;
  }
} // namespace pdns
