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

#include <boost/tokenizer.hpp>
#include <boost/format.hpp>

#include "namespaces.hh"
#include "ws-api.hh"
#include "json.hh"
#include "version.hh"
#include "arguments.hh"
#include "dnsparser.hh"
#ifdef RECURSOR
#include "syncres.hh"
#else
#include "responsestats.hh"
#include "statbag.hh"
#endif
#include <cstdio>
#include <cstring>
#include <cctype>
#include <sys/types.h>
#include <iomanip>

using json11::Json;

#ifndef RECURSOR
extern StatBag S;
#endif

static Json getServerDetail()
{
  return Json::object{
    {"type", "Server"},
    {"id", "localhost"},
    {"url", "/api/v1/servers/localhost"},
    {"daemon_type", productTypeApiType()},
    {"version", getPDNSVersion()},
    {"config_url", "/api/v1/servers/localhost/config{/config_setting}"},
    {"zones_url", "/api/v1/servers/localhost/zones{/zone}"},
#ifndef RECURSOR
    {"autoprimaries_url", "/api/v1/servers/localhost/autoprimaries{/autoprimary}"}
#endif
  };
}

/* Return information about the supported API versions.
 * The format of this MUST NEVER CHANGE at it's not versioned.
 */
void apiDiscovery(HttpRequest* /* req */, HttpResponse* resp)
{
  Json version1 = Json::object{
    {"version", 1},
    {"url", "/api/v1"}};
  Json doc = Json::array{std::move(version1)};

  resp->setJsonBody(doc);
}

void apiDiscoveryV1(HttpRequest* /* req */, HttpResponse* resp)
{
  const Json& version1 = Json::object{
    {"server_url", "/api/v1/servers{/server}"},
    {"api_features", Json::array{}}};
  const Json& doc = Json::array{version1};

  resp->setJsonBody(doc);
}

void apiServer(HttpRequest* /* req */, HttpResponse* resp)
{
  const Json& doc = Json::array{getServerDetail()};
  resp->setJsonBody(doc);
}

void apiServerDetail(HttpRequest* /* req */, HttpResponse* resp)
{
  resp->setJsonBody(getServerDetail());
}

void apiServerConfig(HttpRequest* /* req */, HttpResponse* resp)
{
  const vector<string>& items = ::arg().list();
  string value;
  Json::array doc;
  for (const string& item : items) {
    if (item.find("password") != string::npos || item.find("api-key") != string::npos) {
      value = "***";
    }
    else {
      value = ::arg()[item];
    }

    doc.push_back(Json::object{
      {"type", "ConfigSetting"},
      {"name", item},
      {"value", value},
    });
  }
  resp->setJsonBody(doc);
}

void apiServerStatistics(HttpRequest* req, HttpResponse* resp)
{
  Json::array doc;
  string name = req->getvars["statistic"];
  if (!name.empty()) {
    const auto& stat = productServerStatisticsFetch(name);
    if (!stat) {
      throw ApiException("Unknown statistic name");
    }

    doc.push_back(Json::object{
      {"type", "StatisticItem"},
      {"name", name},
      {"value", std::to_string(*stat)},
    });

    resp->setJsonBody(doc);

    return;
  }

  typedef map<string, string> stat_items_t;
  stat_items_t general_stats;
  productServerStatisticsFetch(general_stats);

  for (const auto& item : general_stats) {
    doc.push_back(Json::object{
      {"type", "StatisticItem"},
      {"name", item.first},
      {"value", item.second},
    });
  }

#ifdef RECURSOR
  auto stats = g_Counters.sum(rec::ResponseStats::responseStats);
  auto resp_qtype_stats = stats.getQTypeResponseCounts();
  auto resp_size_stats = stats.getSizeResponseCounts();
  auto resp_rcode_stats = stats.getRCodeResponseCounts();
#else
  auto resp_qtype_stats = g_rs.getQTypeResponseCounts();
  auto resp_size_stats = g_rs.getSizeResponseCounts();
  auto resp_rcode_stats = g_rs.getRCodeResponseCounts();
#endif
  {
    Json::array values;
    for (const auto& item : resp_qtype_stats) {
      if (item.second == 0) {
        continue;
      }
      values.push_back(Json::object{
        {"name", DNSRecordContent::NumberToType(item.first)},
        {"value", std::to_string(item.second)},
      });
    }

    doc.push_back(Json::object{
      {"type", "MapStatisticItem"},
      {"name", "response-by-qtype"},
      {"value", values},
    });
  }

  {
    Json::array values;
    for (const auto& item : resp_size_stats) {
      if (item.second == 0) {
        continue;
      }

      values.push_back(Json::object{
        {"name", std::to_string(item.first)},
        {"value", std::to_string(item.second)},
      });
    }

    doc.push_back(Json::object{
      {"type", "MapStatisticItem"},
      {"name", "response-sizes"},
      {"value", values},
    });
  }

  {
    Json::array values;
    for (const auto& item : resp_rcode_stats) {
      if (item.second == 0) {
        continue;
      }

      values.push_back(Json::object{
        {"name", RCode::to_s(item.first)},
        {"value", std::to_string(item.second)},
      });
    }

    doc.push_back(Json::object{
      {"type", "MapStatisticItem"},
      {"name", "response-by-rcode"},
      {"value", values},
    });
  }

#ifndef RECURSOR
  if ((req->getvars.count("includerings") == 0) || req->getvars["includerings"] != "false") {
    for (const auto& ringName : S.listRings()) {
      Json::array values;
      const auto& ring = S.getRing(ringName);
      for (const auto& item : ring) {
        if (item.second == 0) {
          continue;
        }

        values.push_back(Json::object{
          {"name", item.first},
          {"value", std::to_string(item.second)},
        });
      }

      doc.push_back(Json::object{
        {"type", "RingStatisticItem"},
        {"name", ringName},
        {"size", std::to_string(S.getRingSize(ringName))},
        {"value", values},
      });
    }
  }
#endif

  resp->setJsonBody(doc);
}

DNSName apiNameToDNSName(const string& name)
{
  if (!isCanonical(name)) {
    throw ApiException("DNS Name '" + name + "' is not canonical");
  }
  try {
    return DNSName(name);
  }
  catch (...) {
    throw ApiException("Unable to parse DNS Name '" + name + "'");
  }
}

#if defined(PDNS_AUTH)
ZoneName apiNameToZoneName(const string& name)
{
  // Split the variant name, if any, in order to be able to invoke
  // isCanonical on the right subset.
  if (auto sep = ZoneName::findVariantSeparator(name); sep != std::string_view::npos) {
    if (!isCanonical(std::string_view(name).substr(0, sep))) {
      throw ApiException("Zone Name '" + name + "' is not canonical");
    }
    try {
      return ZoneName(name, sep);
    }
    catch (...) {
      throw ApiException("Unable to parse Zone Name '" + name + "'");
    }
  }
  return ZoneName(apiNameToDNSName(name));
}
#endif

ZoneName apiZoneIdToName(const string& identifier)
{
  string zonename;
  ostringstream outputStringStream;

  if (identifier.empty()) {
    throw HttpBadRequestException();
  }

  std::size_t lastpos = 0;
  std::size_t pos = 0;
  while ((pos = identifier.find('=', lastpos)) != string::npos) {
    outputStringStream << identifier.substr(lastpos, pos - lastpos);
    char currentChar{};
    // decode tens
    if (identifier[pos + 1] >= '0' && identifier[pos + 1] <= '9') {
      currentChar = static_cast<char>(identifier[pos + 1] - '0');
    }
    else if (identifier[pos + 1] >= 'A' && identifier[pos + 1] <= 'F') {
      currentChar = static_cast<char>(identifier[pos + 1] - 'A' + 10);
    }
    else {
      throw HttpBadRequestException();
    }
    currentChar = static_cast<char>(currentChar * 16);

    // decode unit place
    if (identifier[pos + 2] >= '0' && identifier[pos + 2] <= '9') {
      currentChar = static_cast<char>(currentChar + identifier[pos + 2] - '0');
    }
    else if (identifier[pos + 2] >= 'A' && identifier[pos + 2] <= 'F') {
      currentChar = static_cast<char>(currentChar + identifier[pos + 2] - 'A' + 10);
    }
    else {
      throw HttpBadRequestException();
    }

    outputStringStream << currentChar;

    lastpos = pos + 3;
  }
  if (lastpos < pos) {
    outputStringStream << identifier.substr(lastpos, pos - lastpos);
  }

  zonename = outputStringStream.str();

  try {
    return ZoneName(zonename);
  }
  catch (...) {
    throw ApiException("Unable to parse DNS Name '" + zonename + "'");
  }
}

string apiZoneNameToId(const ZoneName& dname)
{
  return apiNameToId(dname.toString());
}

string apiNameToId(const string& name)
{
  ostringstream outputStringStream;

  for (char iter : name) {
    if ((iter >= 'A' && iter <= 'Z') || (iter >= 'a' && iter <= 'z') || (iter >= '0' && iter <= '9') || (iter == '.') || (iter == '-')) {
      outputStringStream << iter;
    }
    else {
      outputStringStream << (boost::format("=%02X") % (int)iter);
    }
  }

  string identifier = outputStringStream.str();

  // add trailing dot
  if (identifier.empty() || identifier.substr(identifier.size() - 1) != ".") {
    identifier += ".";
  }

  // special handling for the root zone, as a dot on it's own doesn't work
  // everywhere.
  if (identifier == ".") {
    identifier = (boost::format("=%02X") % (int)('.')).str();
  }
  return identifier;
}

void apiCheckNameAllowedCharacters(std::string_view name)
{
  if (name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890_/.-") != std::string::npos) {
    throw ApiException("Name '" + std::string(name) + "' contains unsupported characters");
  }
}

void apiCheckQNameAllowedCharacters(std::string_view qname)
{
  if (qname.compare(0, 2, "*.") == 0) {
    apiCheckNameAllowedCharacters(qname.substr(2));
  }
  else {
    apiCheckNameAllowedCharacters(qname);
  }
}
