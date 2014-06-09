/*
    Copyright (C) 2002 - 2014  PowerDNS.COM BV

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
#include <boost/foreach.hpp>
#include <boost/tokenizer.hpp>
#include <boost/circular_buffer.hpp>
#include "namespaces.hh"
#include "ws-api.hh"
#include "json.hh"
#include "config.h"
#include "version.hh"
#include "arguments.hh"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <iomanip>

extern string s_programname;

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

using namespace rapidjson;

static void fillServerDetail(Value& out, Value::AllocatorType& allocator)
{
  Value jdaemonType(productTypeApiType().c_str(), allocator);
  out.SetObject();
  out.AddMember("type", "Server", allocator);
  out.AddMember("id", "localhost", allocator);
  out.AddMember("url", "/servers/localhost", allocator);
  out.AddMember("daemon_type", jdaemonType, allocator);
  out.AddMember("version", VERSION, allocator);
  out.AddMember("config_url", "/servers/localhost/config{/config_setting}", allocator);
  out.AddMember("zones_url", "/servers/localhost/zones{/zone}", allocator);
}

void apiServer(HttpRequest* req, HttpResponse* resp) {
  if(req->method != "GET")
    throw HttpMethodNotAllowedException();

  Document doc;
  doc.SetArray();
  Value server;
  fillServerDetail(server, doc.GetAllocator());
  doc.PushBack(server, doc.GetAllocator());
  resp->setBody(doc);
}

void apiServerDetail(HttpRequest* req, HttpResponse* resp) {
  if(req->method != "GET")
    throw HttpMethodNotAllowedException();

  Document doc;
  fillServerDetail(doc, doc.GetAllocator());
  resp->setBody(doc);
}

void apiServerConfig(HttpRequest* req, HttpResponse* resp) {
  if(req->method != "GET")
    throw HttpMethodNotAllowedException();

  vector<string> items = ::arg().list();
  string value;
  Document doc;
  doc.SetArray();
  BOOST_FOREACH(const string& item, items) {
    Value jitem;
    jitem.SetObject();
    jitem.AddMember("type", "ConfigSetting", doc.GetAllocator());

    Value jname(item.c_str(), doc.GetAllocator());
    jitem.AddMember("name", jname, doc.GetAllocator());

    if(item.find("password") != string::npos)
      value = "***";
    else
      value = ::arg()[item];

    Value jvalue(value.c_str(), doc.GetAllocator());
    jitem.AddMember("value", jvalue, doc.GetAllocator());

    doc.PushBack(jitem, doc.GetAllocator());
  }
  resp->setBody(doc);
}

static string logGrep(const string& q, const string& fname, const string& prefix)
{
  FILE* ptr = fopen(fname.c_str(), "r");
  if(!ptr) {
    throw ApiException("Opening \"" + fname + "\" failed: " + stringerror());
  }
  boost::shared_ptr<FILE> fp(ptr, fclose);

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

  Document doc;
  doc.SetArray();
  if(!lines.empty()) {
    BOOST_FOREACH(const string& line, lines) {
      doc.PushBack(line.c_str(), doc.GetAllocator());
    }
  }
  return makeStringFromDocument(doc);
}

void apiServerSearchLog(HttpRequest* req, HttpResponse* resp) {
  if(req->method != "GET")
    throw HttpMethodNotAllowedException();

  string prefix = " " + s_programname + "[";
  resp->body = logGrep(req->getvars["q"], ::arg()["experimental-logfile"], prefix);
}

void apiServerStatistics(HttpRequest* req, HttpResponse* resp) {
  if(req->method != "GET")
    throw HttpMethodNotAllowedException();

  map<string,string> items;
  productServerStatisticsFetch(items);

  Document doc;
  doc.SetArray();
  typedef map<string, string> items_t;
  BOOST_FOREACH(const items_t::value_type& item, items) {
    Value jitem;
    jitem.SetObject();
    jitem.AddMember("type", "StatisticItem", doc.GetAllocator());

    Value jname(item.first.c_str(), doc.GetAllocator());
    jitem.AddMember("name", jname, doc.GetAllocator());

    Value jvalue(item.second.c_str(), doc.GetAllocator());
    jitem.AddMember("value", jvalue, doc.GetAllocator());

    doc.PushBack(jitem, doc.GetAllocator());
  }

  resp->setBody(doc);
}

string apiZoneIdToName(const string& id) {
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

  // strip trailing dot
  if (zonename.substr(zonename.size()-1) == ".") {
    zonename.resize(zonename.size()-1);
  }
  return zonename;
}

string apiZoneNameToId(const string& name) {
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
  if (id.substr(id.size()-1) != ".") {
    id += ".";
  }

  // special handling for the root zone, as a dot on it's own doesn't work
  // everywhere.
  if (id == ".") {
    id = (boost::format("=%02x") % (int)('.')).str();
  }
  return id;
}
