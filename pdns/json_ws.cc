/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2003 - 2012  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 
    as published by the Free Software Foundation

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
  char * p = strchr(buffer, '\r');
  if(p) *p = 0;
  vector<string> parts;
  stringtok(parts, buffer);
  string method, uri;
  if(parts.size()>1) {
    method=parts[0];
    uri=parts[1];
  }

  string content;

  string status = "200 OK";
  string headers = "Date: Wed, 30 Nov 2012 22:01:15 GMT\r\n"
  "Server: PowerDNS Recursor/"VERSION"\r\n"
  "Connection: keep-alive\r\n";

  if (method != "GET") {
    status = "400 Bad Request";
    content = "Your client sent a request this server does not understand.\n";
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
  string callback = varmap["callback"];

  headers += "Access-Control-Allow-Origin: *\r\n";
  headers += "Content-Type: application/json\r\n";

  string content;
  if(!callback.empty())
    content=callback+"(";

  map<string, string> stats; 
  if(varmap["command"] =="domains") {
    content += "[";
    bool first=1;
    BOOST_FOREACH(const SyncRes::domainmap_t::value_type& val, *t_sstorage->domainmap) {
      if(!first) content+= ", ";
      first=false;
      stats.clear();
      stats["name"] = val.first;
      stats["type"] = val.second.d_servers.empty() ? "Native" : "Forwarded";
      stats["servers"];
      BOOST_FOREACH(const ComboAddress& server, val.second.d_servers) {
        stats["servers"]+= server.toStringWithPort() + " ";
      }
      stats["rdbit"] = lexical_cast<string>(val.second.d_servers.empty() ? 0 : val.second.d_rdForward);
      // fill out forwarders too one day, and rdrequired
      content += returnJSONObject(stats);
    }
    content += "]";
  }
  else if(varmap["command"] =="get-zone") {
    SyncRes::domainmap_t::const_iterator ret = t_sstorage->domainmap->find(varmap["zone"]);
    
    content += "[";
    bool first=1;
    
    if(ret != t_sstorage->domainmap->end()) {
      BOOST_FOREACH(const SyncRes::AuthDomain::records_t::value_type& val, ret->second.d_records) {
	if(!first) content+= ", ";
	first=false;
	stats.clear();
	stats["name"] = val.qname;
	stats["type"] = val.qtype.getName();
	stats["ttl"] = lexical_cast<string>(val.ttl);
	stats["priority"] = lexical_cast<string>(val.priority);
	stats["content"] = val.content;
	content += returnJSONObject(stats);
      }
    }
    content += "]";
  }  
  else if(varmap["command"]=="flush-cache") {
    string canon=toCanonic("", varmap["domain"]);
    int count = broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeCache, canon));
    count+=broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeAndCountNegCache, canon));
    stats["number"]=lexical_cast<string>(count);
    content += returnJSONObject(stats);  
  }
  else if(varmap["command"] == "config") {
    vector<string> items = ::arg().list();
    BOOST_FOREACH(const string& var, items) {
      stats[var] = ::arg()[var];
    }
    content += returnJSONObject(stats);  
  }
  else if(varmap["command"]=="log-grep") {
    content += makeLogGrepJSON(varmap, ::arg()["experimental-logfile"], " pdns_recursor[");
  }
  else { //  if(varmap["command"] == "stats") {
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
