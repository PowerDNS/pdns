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
  setSocketReusable(d_socket);
  ComboAddress local("::", 8082);
  bind(d_socket, (struct sockaddr*)&local, local.getSocklen());
  listen(d_socket, 5);
  
  d_fdm->addReadFD(d_socket, boost::bind(&JWebserver::newConnection, this));
}

void JWebserver::readRequest(int fd)
{
  char buffer[16384];
  int res = read(fd, buffer, sizeof(buffer));
  if(res <= 0) {
    d_fdm->removeReadFD(fd);
    close(fd);
    cerr<<"Lost connection"<<endl;
    return;
  }
  buffer[res]=0;
  cerr<< buffer << endl;
  
  char * p = strchr(buffer, '\r');
  if(p) *p = 0;
  if(strstr(buffer, "GET ") != buffer) {
    d_fdm->removeReadFD(fd);
    close(fd);
    cerr<<"Invalid request"<<endl;
    return;
  }

    
  map<string, string> varmap;
  if((p = strchr(buffer, '?'))) {
    vector<string> variables;
    string line(p+1);
    line.resize(line.length() - strlen(" HTTP/1.0"));
    
    stringtok(variables, line, "&");
    BOOST_FOREACH(const string& var, variables) {
      varmap.insert(splitField(var, '='));
      cout<<"Variable: '"<<var<<"'"<<endl;
    }
  }
  
  string callback=varmap["callback"];
  cout <<"Callback: '"<<callback<<"'\n";

  char response[]="HTTP/1.1 200 OK\r\n"
  "Date: Wed, 30 Nov 2011 22:01:15 GMT\r\n"
  "Server: PowerDNS Recursor "VERSION"\r\n"
  "Connection: keep-alive\r\n"
  "Content-Length: %d\r\n"
  "Access-Control-Allow-Origin: *\r\n"
  "Content-Type: application/json\r\n"
  "\r\n" ;
  

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
  else if(varmap["command"]=="flush-cache") {
    string canon=toCanonic("", varmap["domain"]);
    cerr<<"Canon: '"<<canon<<"'\n";
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
    content += makeLogGrepJSON(varmap, ::arg()["logfile"], " pdns_recursor[");
  }
  else { //  if(varmap["command"] == "stats") {
    stats = getAllStatsMap();
    content += returnJSONObject(stats);  
  } 

  if(!callback.empty())
    content += ");";

  string tot = (boost::format(response) % content.length()).str();
  tot += content;
  cout << "Starting write"<<endl;
  Utility::setBlocking(fd);
  writen2(fd, tot.c_str(), tot.length());
  Utility::setNonBlocking(fd);
  cout <<"And done"<<endl;
}

void JWebserver::newConnection()
{
  ComboAddress remote;
  remote.sin4.sin_family=AF_INET6;
  socklen_t remlen = remote.getSocklen();
  int sock = accept(d_socket, (struct sockaddr*) &remote, &remlen);
  if(sock < 0)
    return;
    
  cerr<<"Connection from "<< remote.toStringWithPort() <<endl;
  Utility::setNonBlocking(sock);
  d_fdm->addReadFD(sock, boost::bind(&JWebserver::readRequest, this, _1));
}
