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
#include "namespaces.hh"
#include "ws-api.hh"
#include "json.hh"
#include "version.hh"
#include "arguments.hh"
#include "dnsparser.hh"
#include "responsestats.hh"
#ifndef RECURSOR
#include "statbag.hh"
#endif
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <iomanip>

using json11::Json;

extern string s_programname;
extern ResponseStats g_rs;
#ifndef RECURSOR
extern StatBag S;
#endif

#ifndef HAVE_STRCASESTR

/*
 * strcasestr() locates the first occurrence in the string s1 of the
 * sequence of characters (excluding the terminating null character)
 * in the string s2, ignoring case.  strcasestr() returns a pointer
 * to the located string, or a null pointer if the string is not found.
 * If s2 is empty, the function returns s1.
 */

static char *
strcasestr(const char *s1, const char *s2)
{
        int *cm = __trans_lower;
        const uchar_t *us1 = (const uchar_t *)s1;
        const uchar_t *us2 = (const uchar_t *)s2;
        const uchar_t *tptr;
        int c;

        if (us2 == NULL || *us2 == '\0')
                return ((char *)us1);

        c = cm[*us2];
        while (*us1 != '\0') {
                if (c == cm[*us1++]) {
                        tptr = us1;
                        while (cm[c = *++us2] == cm[*us1++] && c != '\0')
                                continue;
                        if (c == '\0')
                                return ((char *)tptr - 1);
                        us1 = tptr;
                        us2 = (const uchar_t *)s2;
                        c = cm[*us2];
                }
        }

        return (NULL);
}

#endif // HAVE_STRCASESTR

static Json getServerDetail() {
  return Json::object {
    { "type", "Server" },
    { "id", "localhost" },
    { "url", "/api/v1/servers/localhost" },
    { "daemon_type", productTypeApiType() },
    { "version", getPDNSVersion() },
    { "config_url", "/api/v1/servers/localhost/config{/config_setting}" },
    { "zones_url", "/api/v1/servers/localhost/zones{/zone}" }
  };
}

/* Return information about the supported API versions.
 * The format of this MUST NEVER CHANGE at it's not versioned.
 */
void apiDiscovery(HttpRequest* req, HttpResponse* resp) {
  if(req->method != "GET")
    throw HttpMethodNotAllowedException();

  Json version1 = Json::object {
    { "version", 1 },
    { "url", "/api/v1" }
  };
  Json doc = Json::array { version1 };

  resp->setBody(doc);
}

void apiServer(HttpRequest* req, HttpResponse* resp) {
  if(req->method != "GET")
    throw HttpMethodNotAllowedException();

  Json doc = Json::array {getServerDetail()};
  resp->setBody(doc);
}

void apiServerDetail(HttpRequest* req, HttpResponse* resp) {
  if(req->method != "GET")
    throw HttpMethodNotAllowedException();

  resp->setBody(getServerDetail());
}

void apiServerConfig(HttpRequest* req, HttpResponse* resp) {
  if(req->method != "GET")
    throw HttpMethodNotAllowedException();

  vector<string> items = ::arg().list();
  string value;
  Json::array doc;
  for(const string& item : items) {
    if(item.find("password") != string::npos || item.find("api-key") != string::npos)
      value = "***";
    else
      value = ::arg()[item];

    doc.push_back(Json::object {
      { "type", "ConfigSetting" },
      { "name", item },
      { "value", value },
    });
  }
  resp->setBody(doc);
}

void apiServerStatistics(HttpRequest* req, HttpResponse* resp) {
  if(req->method != "GET")
    throw HttpMethodNotAllowedException();

  Json::array doc;
  string name = req->getvars["statistic"];
  if (!name.empty()) {
    auto stat = productServerStatisticsFetch(name);
    if (!stat) {
      throw ApiException("Unknown statistic name");
    }

    doc.push_back(Json::object {
      { "type", "StatisticItem" },
      { "name", name },
      { "value", std::to_string(*stat) },
    });

    resp->setBody(doc);

    return;
  }

  typedef map<string, string> stat_items_t;
  stat_items_t general_stats;
  productServerStatisticsFetch(general_stats);

  for(const auto& item : general_stats) {
    doc.push_back(Json::object {
      { "type", "StatisticItem" },
      { "name", item.first },
      { "value", item.second },
    });
  }

  auto resp_qtype_stats = g_rs.getQTypeResponseCounts();
  auto resp_size_stats = g_rs.getSizeResponseCounts();
  auto resp_rcode_stats = g_rs.getRCodeResponseCounts();
  {
    Json::array values;
    for(const auto& item : resp_qtype_stats) {
      if (item.second == 0)
        continue;
      values.push_back(Json::object {
        { "name", DNSRecordContent::NumberToType(item.first) },
        { "value", std::to_string(item.second) },
      });
    }

    doc.push_back(Json::object {
      { "type", "MapStatisticItem" },
      { "name", "response-by-qtype" },
      { "value", values },
    });
  }

  {
    Json::array values;
    for(const auto& item : resp_size_stats) {
      if (item.second == 0)
        continue;

      values.push_back(Json::object {
        { "name", std::to_string(item.first) },
        { "value", std::to_string(item.second) },
      });
    }

    doc.push_back(Json::object {
      { "type", "MapStatisticItem" },
      { "name", "response-sizes" },
      { "value", values },
    });
  }

  {
    Json::array values;
    for(const auto& item : resp_rcode_stats) {
      if (item.second == 0)
        continue;
      values.push_back(Json::object {
        { "name", RCode::to_s(item.first) },
        { "value", std::to_string(item.second) },
      });
    }

    doc.push_back(Json::object {
      { "type", "MapStatisticItem" },
      { "name", "response-by-rcode" },
      { "value", values },
    });
  }

#ifndef RECURSOR
  for(const auto& ringName : S.listRings()) {
    Json::array values;
    const auto& ring = S.getRing(ringName);
    for(const auto& item : ring) {
      if (item.second == 0)
        continue;

      values.push_back(Json::object {
        { "name", item.first },
        { "value", std::to_string(item.second) },
      });
    }

    doc.push_back(Json::object {
      { "type", "RingStatisticItem" },
      { "name", ringName },
      { "size", std::to_string(S.getRingSize(ringName)) },
      { "value", values },
    });
  }
#endif

  resp->setBody(doc);
}

DNSName apiNameToDNSName(const string& name) {
  if (!isCanonical(name)) {
    throw ApiException("DNS Name '" + name + "' is not canonical");
  }
  try {
    return DNSName(name);
  } catch (...) {
    throw ApiException("Unable to parse DNS Name '" + name + "'");
  }
}

DNSName apiZoneIdToName(const string& id) {
  string zonename;
  ostringstream ss;

  if(id.empty())
    throw HttpBadRequestException();

  std::size_t lastpos = 0, pos = 0;
  while ((pos = id.find('=', lastpos)) != string::npos) {
    ss << id.substr(lastpos, pos-lastpos);
    char c;
    // decode tens
    if (id[pos+1] >= '0' && id[pos+1] <= '9') {
      c = id[pos+1] - '0';
    } else if (id[pos+1] >= 'A' && id[pos+1] <= 'F') {
      c = id[pos+1] - 'A' + 10;
    } else {
      throw HttpBadRequestException();
    }
    c = c * 16;

    // decode unit place
    if (id[pos+2] >= '0' && id[pos+2] <= '9') {
      c += id[pos+2] - '0';
    } else if (id[pos+2] >= 'A' && id[pos+2] <= 'F') {
      c += id[pos+2] - 'A' + 10;
    } else {
      throw HttpBadRequestException();
    }

    ss << c;

    lastpos = pos+3;
  }
  if (lastpos < pos) {
    ss << id.substr(lastpos, pos-lastpos);
  }

  zonename = ss.str();

  try {
    return DNSName(zonename);
  } catch (...) {
    throw ApiException("Unable to parse DNS Name '" + zonename + "'");
  }
}

string apiZoneNameToId(const DNSName& dname) {
  string name=dname.toString();
  ostringstream ss;

  for(string::const_iterator iter = name.begin(); iter != name.end(); ++iter) {
    if ((*iter >= 'A' && *iter <= 'Z') ||
        (*iter >= 'a' && *iter <= 'z') ||
        (*iter >= '0' && *iter <= '9') ||
        (*iter == '.') || (*iter == '-')) {
      ss << *iter;
    } else {
      ss << (boost::format("=%02X") % (int)(*iter));
    }
  }

  string id = ss.str();

  // add trailing dot
  if (id.size() == 0 || id.substr(id.size()-1) != ".") {
    id += ".";
  }

  // special handling for the root zone, as a dot on it's own doesn't work
  // everywhere.
  if (id == ".") {
    id = (boost::format("=%02X") % (int)('.')).str();
  }
  return id;
}

void apiCheckNameAllowedCharacters(const string& name) {
  if (name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890_/.-") != std::string::npos)
    throw ApiException("Name '"+name+"' contains unsupported characters");
}

void apiCheckQNameAllowedCharacters(const string& qname) {
  if (qname.compare(0, 2, "*.") == 0) apiCheckNameAllowedCharacters(qname.substr(2));
  else apiCheckNameAllowedCharacters(qname);
}
