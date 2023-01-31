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
#include <limits>

#include "ednsextendederror.hh"

static bool getEDNSExtendedErrorOptFromStringView(const std::string_view& option, EDNSExtendedError& eee)
{
  if (option.size() < sizeof(uint16_t)) {
    return false;
  }
  eee.infoCode = static_cast<uint8_t>(option.at(0)) * 256 + static_cast<uint8_t>(option.at(1));

  if (option.size() > sizeof(uint16_t)) {
    eee.extraText = std::string(&option.at(sizeof(uint16_t)), option.size() - sizeof(uint16_t));
  }

  return true;
}

bool getEDNSExtendedErrorOptFromString(const string& option, EDNSExtendedError& eee)
{
  return getEDNSExtendedErrorOptFromStringView(std::string_view(option), eee);
}

bool getEDNSExtendedErrorOptFromString(const char* option, unsigned int len, EDNSExtendedError& eee)
{
  return getEDNSExtendedErrorOptFromStringView(std::string_view(option, len), eee);
}

string makeEDNSExtendedErrorOptString(const EDNSExtendedError& eee)
{
  if (eee.extraText.size() > static_cast<size_t>(std::numeric_limits<uint16_t>::max() - 2)) {
    throw std::runtime_error("Trying to create an EDNS Extended Error option with an extra text of size " + std::to_string(eee.extraText.size()));
  }

  string ret;
  ret.reserve(sizeof(uint16_t) + eee.extraText.size());
  ret.resize(sizeof(uint16_t));

  ret[0] = static_cast<char>(static_cast<uint16_t>(eee.infoCode) / 256);
  ret[1] = static_cast<char>(static_cast<uint16_t>(eee.infoCode) % 256);
  ret.append(eee.extraText);

  return ret;
}
