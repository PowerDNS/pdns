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
#include "json.hh"
#include "namespaces.hh"
#include "misc.hh"

using json11::Json;

static inline int intFromJsonInternal(const Json& container, const std::string& key, const bool have_default, const int default_value)
{
  const auto& val = container[key];
  if (val.is_number()) {
    return val.int_value();
  }

  if (val.is_string()) {
    try {
      return std::stoi(val.string_value());
    } catch (std::out_of_range&) {
      throw JsonException("Key '" + string(key) + "' is out of range");
    }
  }

  if (have_default) {
    return default_value;
  }
  throw JsonException("Key '" + string(key) + "' not an Integer or not present");
}

int intFromJson(const Json& container, const std::string& key)
{
  return intFromJsonInternal(container, key, false, 0);
}

int intFromJson(const Json& container, const std::string& key, const int default_value)
{
  return intFromJsonInternal(container, key, true, default_value);
}

static inline unsigned int uintFromJsonInternal(const Json& container, const std::string& key, const bool have_default, const unsigned int default_value)
{
  int intval = intFromJsonInternal(container, key, have_default, static_cast<int>(default_value));
  if (intval >= 0) {
    return intval;
  }
  throw JsonException("Key '" + string(key) + "' is not a positive Integer");
}

unsigned int uintFromJson(const Json& container, const std::string& key)
{
  return uintFromJsonInternal(container, key, false, 0);
}

unsigned int uintFromJson(const Json& container, const std::string& key, const unsigned int default_value)
{
  return uintFromJsonInternal(container, key, true, default_value);
}

static inline double doubleFromJsonInternal(const Json& container, const std::string& key, const bool have_default, const double default_value)
{
  const auto& val = container[key];
  if (val.is_number()) {
    return val.number_value();
  }

  if (val.is_string()) {
    try {
      return std::stod(val.string_value());
    } catch (std::out_of_range&) {
      throw JsonException("Value for key '" + string(key) + "' is out of range");
    }
  }

  if (have_default) {
    return default_value;
  }
  throw JsonException("Key '" + string(key) + "' not an Integer or not present");
}

double doubleFromJson(const Json& container, const std::string& key)
{
  return doubleFromJsonInternal(container, key, false, 0);
}

double doubleFromJson(const Json& container, const std::string& key, const double default_value)
{
  return doubleFromJsonInternal(container, key, true, default_value);
}

string stringFromJson(const Json& container, const std::string &key)
{
  const auto& val = container[key];
  if (val.is_string()) {
    return val.string_value();
  }
  throw JsonException("Key '" + string(key) + "' not present or not a String");
}

static inline bool boolFromJsonInternal(const Json& container, const std::string& key, const bool have_default, const bool default_value)
{
  const auto& val = container[key];
  if (val.is_bool()) {
    return val.bool_value();
  }
  if (have_default) {
    return default_value;
  }
  throw JsonException("Key '" + string(key) + "' not present or not a Bool");
}

bool boolFromJson(const Json& container, const std::string& key)
{
  return boolFromJsonInternal(container, key, false, false);
}

bool boolFromJson(const Json& container, const std::string& key, const bool default_value)
{
  return boolFromJsonInternal(container, key, true, default_value);
}
