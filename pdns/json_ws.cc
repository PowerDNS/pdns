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
#include "json_ws.hh"
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
#include "config.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

using namespace rapidjson;

JWebserver::JWebserver(FDMultiplexer* fdm) : d_fdm(fdm)
{
  RecursorControlParser rcp; // inits
  d_socket = socket(AF_INET6, SOCK_STREAM, 0);
  if(d_socket<0) {
    throw PDNSException("Making webserver socket: "+stringerror());
  }
  setSocketReusable(d_socket);
  ComboAddress local("::", 8082);
  if(bind(d_socket, (struct sockaddr*)&local, local.getSocklen())<0) {
    throw PDNSException("Binding webserver socket: "+stringerror());
  }
  listen(d_socket, 5);
  
  d_fdm->addReadFD(d_socket, boost::bind(&JWebserver::newConnection, this));
}

void JWebserver::readRequest(int fd)
{
  char buffer[16384];
  int res = read(fd, buffer, sizeof(buffer)-1);
  if(res <= 0) {
    d_fdm->removeReadFD(fd);
    close(fd);
    return;
  }
  buffer[res]=0;

  // Note: this code makes it impossible to read the request body.
  // We'll at least need to wait for two \r\n sets to arrive, parse the
  // headers, and then read the body (using the supplied Content-Length).
  char *p = strchr(buffer, '\r');
  if(p) *p = 0;

  vector<string> parts;
  string method, uri;
  if(strlen(buffer) < 2048) {
    stringtok(parts, buffer);
    if(parts.size()>1) {
      method=parts[0];
      uri=parts[1];
    }
  }

  string content;

  string status = "200 OK";
  string headers = "Date: Wed, 30 Nov 2012 22:01:15 GMT\r\n"
  "Server: PowerDNS Recursor/"VERSION"\r\n"
  "Connection: keep-alive\r\n";

  if (method != "GET") {
    status = "400 Bad Request";
    content = "Your client sent a request this server could not understand.\n";
  } else {
    parts.clear();
    stringtok(parts, uri, "?");
    map<string, string> varmap;
    if(parts.size()>1) {
      vector<string> variables;
      stringtok(variables, parts[1], "&");
      BOOST_FOREACH(const string& var, variables) {
        varmap.insert(splitField(var, '='));
      }
    }

    content = handleRequest(method, uri, varmap, headers);
  }

  const char *headers_append = "Content-Length: %d\r\n\r\n";
  string reply = "HTTP/1.1 " + status + "\r\n" + headers +
    (boost::format(headers_append) % content.length()).str() +
    content;

  Utility::setBlocking(fd);
  writen2(fd, reply.c_str(), reply.length());
  Utility::setNonBlocking(fd);
}

string JWebserver::handleRequest(const string &method, const string &uri, const map<string,string> &rovarmap, string &headers)
{
  map<string,string> varmap = rovarmap;
  string callback;
  if (varmap.count("callback")) {
    callback = varmap["callback"];
    varmap.erase("callback");
  }
  string command;
  if (varmap.count("command")) {
    command = varmap["command"];
    varmap.erase("command");
  }

  headers += "Access-Control-Allow-Origin: *\r\n";
  headers += "Content-Type: application/json\r\n";

  string content;
  if(!callback.empty())
    content=callback+"(";

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
    content += makeStringFromDocument(doc);
  }
  else if(command == "zone") {
    SyncRes::domainmap_t::const_iterator ret = t_sstorage->domainmap->find(varmap["zone"]);
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
      content += makeStringFromDocument(doc);
    } else {
      content += returnJSONError("Could not find domain '"+varmap["zone"]+"'");
    }
  }
  else if(command == "flush-cache") {
    string canon=toCanonic("", varmap["domain"]);
    int count = broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeCache, canon));
    count+=broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeAndCountNegCache, canon));
    stats["number"]=lexical_cast<string>(count);
    content += returnJSONObject(stats);  
  }
  else if(command == "config") {
    vector<string> items = ::arg().list();
    BOOST_FOREACH(const string& var, items) {
      stats[var] = ::arg()[var];
    }
    content += returnJSONObject(stats);  
  }
  else if(command == "log-grep") {
    content += makeLogGrepJSON(varmap["needle"], ::arg()["experimental-logfile"], " pdns_recursor[");
  }
  else { //  if(command == "stats") {
    stats = getAllStatsMap();
    content += returnJSONObject(stats);  
  } 

  if(!callback.empty())
    content += ");";

  return content;
}

void JWebserver::newConnection()
{
  ComboAddress remote;
  remote.sin4.sin_family=AF_INET6;
  socklen_t remlen = remote.getSocklen();
  int sock = accept(d_socket, (struct sockaddr*) &remote, &remlen);
  if(sock < 0)
    return;
    
  Utility::setNonBlocking(sock);
  d_fdm->addReadFD(sock, boost::bind(&JWebserver::readRequest, this, _1));
}
