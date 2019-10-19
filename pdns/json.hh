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
#pragma once // it is 2012, deal with it

#include <string>
#include <stdexcept>
#include "json11.hpp"

int intFromJson(const json11::Json container, const std::string& key);
int intFromJson(const json11::Json container, const std::string& key, const int default_value);
double doubleFromJson(const json11::Json container, const std::string& key);
double doubleFromJson(const json11::Json container, const std::string& key, const double default_value);
std::string stringFromJson(const json11::Json container, const std::string &key);
bool boolFromJson(const json11::Json container, const std::string& key);
bool boolFromJson(const json11::Json container, const std::string& key, const bool default_value);

class JsonException : public std::runtime_error
{
public:
  JsonException(const std::string& what_arg) : std::runtime_error(what_arg) {
  }
};
