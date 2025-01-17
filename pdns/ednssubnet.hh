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

#include "iputils.hh"

class EDNSSubnetOpts
{
public:
  void setSource(const Netmask& netmask)
  {
    source = netmask;
  }
  [[nodiscard]] const Netmask& getSource() const
  {
    return source;
  }
  [[nodiscard]] uint8_t getFamily() const
  {
    return source.getNetwork().sin4.sin_family;
  }
  [[nodiscard]] uint8_t getSourcePrefixLength() const
  {
    return source.getBits();
  }
  void setScopePrefixLength(uint8_t scope)
  {
    scopeBits = scope;
  }
  [[nodiscard]] uint8_t getScopePrefixLength() const
  {
    return scopeBits;
  }
  [[nodiscard]] Netmask getScope() const
  {
    return {source.getNetwork(), scopeBits};
  }
  [[nodiscard]] std::string makeOptString() const;
  static bool getFromString(const std::string& options, EDNSSubnetOpts* eso);
  static bool getFromString(const char* options, unsigned int len, EDNSSubnetOpts* eso);

private:
  Netmask source;
  uint8_t scopeBits{};
};
