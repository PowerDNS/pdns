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

int intFromJson(const Json container, const std::string& key)
{
  auto val = container[key];
  if (val.is_number()) {
    return val.int_value();
  } else if (val.is_string()) {
    return std::stoi(val.string_value());
  } else {
    throw JsonException("Key '" + string(key) + "' not an Integer or not present");
  }
}

int intFromJson(const Json container, const std::string& key, const int default_value)
{
  auto val = container[key];
  if (val.is_number()) {
    return val.int_value();
  } else if (val.is_string()) {
    try {
      return std::stoi(val.string_value());
    } catch (std::out_of_range&) {
      throw JsonException("Value for key '" + string(key) + "' is out of range");
    }
  } else {
    // TODO: check if value really isn't present
    return default_value;
  }
}

double doubleFromJson(const Json container, const std::string& key)
{
  auto val = container[key];
  if (val.is_number()) {
    return val.number_value();
  } else if (val.is_string()) {
    try {
      return std::stod(val.string_value());
    } catch (std::out_of_range&) {
      throw JsonException("Value for key '" + string(key) + "' is out of range");
    }
  } else {
    throw JsonException("Key '" + string(key) + "' not an Integer or not present");
  }
}

double doubleFromJson(const Json container, const std::string& key, const double default_value)
{
  auto val = container[key];
  if (val.is_number()) {
    return val.number_value();
  } else if (val.is_string()) {
    return std::stod(val.string_value());
  } else {
    // TODO: check if value really isn't present
    return default_value;
  }
}

string stringFromJson(const Json container, const std::string &key)
{
  const Json val = container[key];
  if (val.is_string()) {
    return val.string_value();
  } else {
    throw JsonException("Key '" + string(key) + "' not present or not a String");
  }
}

bool boolFromJson(const Json container, const std::string& key)
{
  auto val = container[key];
  if (val.is_bool()) {
    return val.bool_value();
  }
  throw JsonException("Key '" + string(key) + "' not present or not a Bool");
}

bool boolFromJson(const Json container, const std::string& key, const bool default_value)
{
  auto val = container[key];
  if (val.is_bool()) {
    return val.bool_value();
  }
  return default_value;
}
