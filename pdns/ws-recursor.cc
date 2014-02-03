/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2003 - 2012  PowerDNS.COM BV

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
#include "ws-recursor.hh"
#include "json.hh"
#include <boost/foreach.hpp>
#include <string>
#include "namespaces.hh"
#include <iostream>
#include "iputils.hh"
#include "rec_channel.hh"
#include "arguments.hh"
#include "misc.hh"
#include "syncres.hh"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "webserver.hh"
#include "ws-api.hh"

using namespace rapidjson;

void productServerStatisticsFetch(map<string,string>& out)
{
  map<string,string> stats = getAllStatsMap();
  out.swap(stats);
}

RecursorWebServer::RecursorWebServer(FDMultiplexer* fdm)
{
  RecursorControlParser rcp; // inits

  if(!arg().mustDo("experimental-webserver"))
    return;

  d_ws = new AsyncWebServer(fdm, arg()["experimental-webserver-address"], arg().asNum("experimental-webserver-port"), arg()["experimental-webserver-password"]);

  // legacy dispatch
  d_ws->registerApiHandler("/jsonstat", boost::bind(&RecursorWebServer::jsonstat, this, _1, _2));
  d_ws->registerApiHandler("/servers/localhost/config", &apiServerConfig);
  d_ws->registerApiHandler("/servers/localhost/search-log", &apiServerSearchLog);
  d_ws->registerApiHandler("/servers/localhost/statistics", &apiServerStatistics);
  d_ws->registerApiHandler("/servers/localhost", &apiServerDetail);
  d_ws->registerApiHandler("/servers", &apiServer);

  d_ws->go();
}

void RecursorWebServer::jsonstat(HttpRequest* req, HttpResponse *resp)
{
  string command;

  if(req->parameters.count("command")) {
    command = req->parameters["command"];
    req->parameters.erase("command");
  }

  map<string, string> stats; 
  if(command == "domains") {
    Document doc;
    doc.SetArray();
    BOOST_FOREACH(const SyncRes::domainmap_t::value_type& val, *t_sstorage->domainmap) {
      Value jzone;
      jzone.SetObject();

      const SyncRes::AuthDomain& zone = val.second;
      Value zonename(val.first.c_str(), doc.GetAllocator());
      jzone.AddMember("name", zonename, doc.GetAllocator());
      jzone.AddMember("type", "Zone", doc.GetAllocator());
      jzone.AddMember("kind", zone.d_servers.empty() ? "Native" : "Forwarded", doc.GetAllocator());
      Value servers;
      servers.SetArray();
      BOOST_FOREACH(const ComboAddress& server, zone.d_servers) {
        Value value(server.toStringWithPort().c_str(), doc.GetAllocator());
        servers.PushBack(value, doc.GetAllocator());
      }
      jzone.AddMember("servers", servers, doc.GetAllocator());
      bool rdbit = zone.d_servers.empty() ? false : zone.d_rdForward;
      jzone.AddMember("rdbit", rdbit, doc.GetAllocator());

      doc.PushBack(jzone, doc.GetAllocator());
    }
    resp->setBody(doc);
    return;
  }
  else if(command == "zone") {
    string arg_zone = req->parameters["zone"];
    SyncRes::domainmap_t::const_iterator ret = t_sstorage->domainmap->find(arg_zone);
    if (ret != t_sstorage->domainmap->end()) {
      Document doc;
      doc.SetObject();
      Value root;
      root.SetObject();

      const SyncRes::AuthDomain& zone = ret->second;
      Value zonename(ret->first.c_str(), doc.GetAllocator());
      root.AddMember("name", zonename, doc.GetAllocator());
      root.AddMember("type", "Zone", doc.GetAllocator());
      root.AddMember("kind", zone.d_servers.empty() ? "Native" : "Forwarded", doc.GetAllocator());
      Value servers;
      servers.SetArray();
      BOOST_FOREACH(const ComboAddress& server, zone.d_servers) {
        Value value(server.toStringWithPort().c_str(), doc.GetAllocator());
        servers.PushBack(value, doc.GetAllocator());
      }
      root.AddMember("servers", servers, doc.GetAllocator());
      bool rdbit = zone.d_servers.empty() ? false : zone.d_rdForward;
      root.AddMember("rdbit", rdbit, doc.GetAllocator());

      Value records;
      records.SetArray();
      BOOST_FOREACH(const SyncRes::AuthDomain::records_t::value_type& rr, zone.d_records) {
        Value object;
        object.SetObject();
        Value jname(rr.qname.c_str(), doc.GetAllocator()); // copy
        object.AddMember("name", jname, doc.GetAllocator());
        Value jtype(rr.qtype.getName().c_str(), doc.GetAllocator()); // copy
        object.AddMember("type", jtype, doc.GetAllocator());
        object.AddMember("ttl", rr.ttl, doc.GetAllocator());
        object.AddMember("priority", rr.priority, doc.GetAllocator());
        Value jcontent(rr.content.c_str(), doc.GetAllocator()); // copy
        object.AddMember("content", jcontent, doc.GetAllocator());
        records.PushBack(object, doc.GetAllocator());
      }
      root.AddMember("records", records, doc.GetAllocator());

      doc.AddMember("zone", root, doc.GetAllocator());
      resp->setBody(doc);
      return;
    } else {
      resp->body = returnJsonError("Could not find domain '"+arg_zone+"'");
      return;
    }
  }
  else if(command == "flush-cache") {
    string canon=toCanonic("", req->parameters["domain"]);
    int count = broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeCache, canon));
    count+=broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeAndCountNegCache, canon));
    stats["number"]=lexical_cast<string>(count);
    resp->body = returnJsonObject(stats);
    return;
  }
  else if(command == "config") {
    vector<string> items = ::arg().list();
    BOOST_FOREACH(const string& var, items) {
      stats[var] = ::arg()[var];
    }
    resp->body = returnJsonObject(stats);
    return;
  }
  else if(command == "log-grep") {
    // legacy parameter name hack
    req->parameters["q"] = req->parameters["needle"];
    apiServerSearchLog(req, resp);
    return;
  }
  else if(command == "stats") {
    stats = getAllStatsMap();
    resp->body = returnJsonObject(stats);
    return;
  } else {
    resp->status = 404;
    resp->body = returnJsonError("Not found");
  }
}
