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

#include <cinttypes>
#include <sstream>
#include <variant>
#include <vector>

#include "rust/lib.rs.h"
#include "misc.hh"

using pdns::rust::settings::rec::AuthZone;
using pdns::rust::settings::rec::ForwardZone;
using pdns::rust::settings::rec::Recursorsettings;

namespace pdns::settings::rec
{
::rust::Vec<::rust::String> getStrings(const std::string& name);
::rust::Vec<ForwardZone> getForwardZones(const std::string& name);
::rust::Vec<AuthZone> getAuthZones(const std::string& name);

inline std::string to_arg(bool arg)
{
  return arg ? "yes" : "no";
}

inline std::string to_arg(uint64_t arg)
{
  return std::to_string(arg);
}

inline std::string to_arg(double arg)
{
  return std::to_string(arg);
}

inline std::string to_arg(const ::rust::String& str)
{
  return std::string(str);
}

std::string to_arg(const AuthZone& authzone);
std::string to_arg(const ForwardZone& forwardzone);

template <typename T>
std::string to_arg(const ::rust::Vec<T>& vec)
{
  std::ostringstream str;
  for (auto iter = vec.begin(); iter != vec.end(); ++iter) {
    if (iter != vec.begin()) {
      str << ',';
    }
    str << to_arg(*iter);
  }
  return str.str();
}

inline void to_yaml(bool& field, const std::string& val)
{
  field = val != "no" && val != "off";
}

inline void to_yaml(::rust::String& field, const std::string& val)
{
  field = val;
}

inline void to_yaml(::rust::Vec<::rust::String>& field, const std::string& val)
{
  stringtok(field, val, ", ;");
}

void to_yaml(uint64_t& field, const std::string& val);
void to_yaml(double& field, const std::string& val);
void to_yaml(::rust::Vec<AuthZone>& field, const std::string& val);
void to_yaml(::rust::Vec<ForwardZone>& field, const std::string& val, bool recurse = false);
}
