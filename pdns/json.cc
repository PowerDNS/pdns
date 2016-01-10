/*
    Copyright (C) 2002 - 2015  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
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
    return std::stoi(val.string_value());
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
    return std::stod(val.string_value());
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
