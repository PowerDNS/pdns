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
#include <boost/circular_buffer.hpp>
#include "namespaces.hh"
#include "ws-api.hh"
#include "json.hh"
#include "version.hh"
#include "arguments.hh"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <iomanip>

extern string s_programname;
using json11::Json;

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

static Json logGrep(const string& q, const string& fname, const string& prefix)
{
  FILE* ptr = fopen(fname.c_str(), "r");
  if(!ptr) {
    throw ApiException("Opening \"" + fname + "\" failed: " + stringerror());
  }
  std::shared_ptr<FILE> fp(ptr, fclose);

  string line;
  string needle = q;
  trim_right(needle);

  boost::replace_all(needle, "%20", " ");
  boost::replace_all(needle, "%22", "\"");

  boost::tokenizer<boost::escaped_list_separator<char> > t(needle, boost::escaped_list_separator<char>("\\", " ", "\""));
  vector<string> matches(t.begin(), t.end());
  matches.push_back(prefix);

  boost::circular_buffer<string> lines(200);
  while(stringfgets(fp.get(), line)) {
    vector<string>::const_iterator iter;
    for(iter = matches.begin(); iter != matches.end(); ++iter) {
      if(!strcasestr(line.c_str(), iter->c_str()))
        break;
    }
    if(iter == matches.end()) {
      trim_right(line);
      lines.push_front(line);
    }
  }

  Json::array items;
  for(const string& iline : lines) {
    items.push_back(iline);
  }
  return items;
}

void apiServerSearchLog(HttpRequest* req, HttpResponse* resp) {
  if(req->method != "GET")
    throw HttpMethodNotAllowedException();

  string prefix = " " + s_programname + "[";
  resp->setBody(logGrep(req->getvars["q"], ::arg()["api-logfile"], prefix));
}

void apiServerStatistics(HttpRequest* req, HttpResponse* resp) {
  if(req->method != "GET")
    throw HttpMethodNotAllowedException();

  map<string,string> items;
  productServerStatisticsFetch(items);

  Json::array doc;
  typedef map<string, string> items_t;
  for(const items_t::value_type& item : items) {
    doc.push_back(Json::object {
      { "type", "StatisticItem" },
      { "name", item.first },
      { "value", item.second },
    });
  }

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
