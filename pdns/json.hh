/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2012  PowerDNS.COM BV

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
#pragma once // it is 2012, deal with it

#include <string>
#include <map>
#include <stdexcept>
#include "rapidjson/document.h"

std::string returnJsonObject(const std::map<std::string, std::string>& items);
std::string returnJsonError(const std::string& error);
std::string returnJsonMessage(const std::string& message);
std::string makeStringFromDocument(const rapidjson::Document& doc);
int intFromJson(const rapidjson::Value& container, const char* key);
int intFromJson(const rapidjson::Value& container, const char* key, const int default_value);
std::string stringFromJson(const rapidjson::Value& container, const char* key);
std::string stringFromJson(const rapidjson::Value& container, const char* key, const std::string& default_value);
bool boolFromJson(const rapidjson::Value& container, const char* key);
bool boolFromJson(const rapidjson::Value& container, const char* key, const bool default_value);

class JsonException : public std::runtime_error
{
public:
  JsonException(const std::string& what) : std::runtime_error(what) {
  }
};
