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
#include "utility.hh"
#include "webserver.hh"
#include "session.hh"
#include "misc.hh"
#include <vector>
#include "logger.hh"
#include <stdio.h>
#include "dns.hh"
#include "base64.hh"
#include "json.hh"


map<string,WebServer::HandlerFunction *>WebServer::d_functions;
void *WebServer::d_that;
string WebServer::d_password;

int WebServer::B64Decode(const std::string& strInput, std::string& strOutput)
{
  return ::B64Decode(strInput, strOutput);
}

void WebServer::registerHandler(const string&s, HandlerFunction *ptr)
{
  d_functions[s]=ptr;
}

void WebServer::setCaller(void *that)
{
  d_that=that;
}

void *WebServer::serveConnection(void *p)
try {
  pthread_detach(pthread_self());
  Session *client=static_cast<Session *>(p);
  bool want_html=false;
  bool want_json=false;

  try {
    string line;
    client->setTimeout(5);
    client->getLine(line);
    stripLine(line);
    if(line.empty())
      throw HttpBadRequestException();
    //    L<<"page: "<<line<<endl;

    vector<string> parts;
    stringtok(parts,line);
    
    string method, uri;
    if(parts.size()>1) {
      method=parts[0];
      uri=parts[1];
    }

    vector<string>variables;

    parts.clear();
    stringtok(parts,uri,"?");

    //    L<<"baseUrl: '"<<parts[0]<<"'"<<endl;
    
    vector<string>urlParts;
    stringtok(urlParts,parts[0],"/");
    string baseUrl;
    if(urlParts.empty())
      baseUrl="";
    else
      baseUrl=urlParts[0];

    //    L<<"baseUrl real: '"<<baseUrl<<"'"<<endl;

    if(parts.size()>1) {
      stringtok(variables,parts[1],"&");
    }

    map<string,string>varmap;

    for(vector<string>::const_iterator i=variables.begin();
        i!=variables.end();++i) {

      parts.clear();
      stringtok(parts,*i,"=");
      if(parts.size()>1)
        varmap[parts[0]]=parts[1];
      else
        varmap[parts[0]]="";

    }

    bool authOK=0;
    int postlen = 0;
    // read & ignore other lines
    do {
      client->getLine(line);
      stripLine(line);

      if(line.empty())
	break;

      size_t colon = line.find(":");
      if(colon==std::string::npos)
	throw HttpBadRequestException();

      string header = toLower(line.substr(0, colon));
      string value = line.substr(line.find_first_not_of(' ', colon+1));

      if(header == "authorization" && toLower(value).find("basic ") == 0) {
        string cookie=value.substr(6);
        string plain;

        B64Decode(cookie,plain);
        vector<string>cparts;
        stringtok(cparts,plain,":");
        // L<<Logger::Error<<"Entered password: '"<<cparts[1].c_str()<<"', should be '"<<d_password.c_str()<<"'"<<endl;
        if(cparts.size()==2 && !strcmp(cparts[1].c_str(),d_password.c_str())) { // this gets rid of terminating zeros
          authOK=1;
        }
      }
      else if(header == "content-length" && method=="POST") {
	postlen = atoi(value.c_str());
//	cout<<"Got a post: "<<postlen<<" bytes"<<endl;
      }
      else if(header == "accept") {
	// json wins over html
	if(value.find("application/json")!=std::string::npos) {
	  want_json=true;
	} else if(value.find("text/html")!=std::string::npos) {
	  want_html=true;
	}
      }
      else
	; // cerr<<"Ignoring line: "<<line<<endl;
      
    } while(true);

    string post;
    if(postlen) 
      post = client->get(postlen);
  
 //   cout<<"Post: '"<<post<<"'"<<endl;

    if(!d_password.empty() && !authOK)
      throw HttpUnauthorizedException();

    HandlerFunction *fptr;
    if(d_functions.count(baseUrl) && (fptr=d_functions[baseUrl])) {
      bool custom=false;
      string ret=(*fptr)(method, post, varmap, d_that, &custom);

      if(!custom) {
        client->putLine("HTTP/1.1 200 OK\n");
        client->putLine("Connection: close\n");
        client->putLine("Content-Type: text/html; charset=utf-8\n\n");
      }
      client->putLine(ret);
    }
    else {
      throw HttpNotFoundException();
    }

  }
  catch(HttpException &e) {
    client->putLine(e.statusLine());
    client->putLine("Connection: close\n");
    client->putLine(e.headers());
    if(want_html) {
      client->putLine("Content-Type: text/html; charset=utf-8\n\n");
      client->putLine("<!html><title>" + e.what() + "</title><h1>" + e.what() + "</h1>");
    } else if (want_json) {
      client->putLine("Content-Type: application/json\n\n");
      client->putLine(returnJSONError(e.what()));
    } else {
      client->putLine("Content-Type: text/plain; charset=utf-8\n\n");
      client->putLine(e.what());
    }
  }

  client->close();
  delete client;
  client=0;

  return 0;
}
catch(SessionTimeoutException &e) {
  // L<<Logger::Error<<"Timeout in webserver"<<endl;
}
catch(PDNSException &e) {
  L<<Logger::Error<<"Exception in webserver: "<<e.reason<<endl;
}
catch(std::exception &e) {
  L<<Logger::Error<<"STL Exception in webserver: "<<e.what()<<endl;
}
catch(...) {
  L<<Logger::Error<<"Unknown exception in webserver"<<endl;
}


WebServer::WebServer(const string &listenaddress, int port, const string &password)
{
  d_listenaddress=listenaddress;
  d_port=port;
  d_password=password;
  d_server = 0; // on exception, this class becomes a NOOP later on
  try {
    d_server = new Server(d_port, d_listenaddress);
  }
  catch(SessionException &e) {
    L<<Logger::Error<<"Fatal error in webserver: "<<e.reason<<endl;
  }
}

void WebServer::go()
{
  if(!d_server)
    return;
  try {
    Session *client;
    pthread_t tid;
    
    L<<Logger::Error<<"Launched webserver on " << d_server->d_local.toStringWithPort() <<endl;

    while((client=d_server->accept())) {
      pthread_create(&tid, 0 , &serveConnection, (void *)client);
    }
  }
  catch(SessionTimeoutException &e) {
    //    L<<Logger::Error<<"Timeout in webserver"<<endl;
  }
  catch(PDNSException &e) {
    L<<Logger::Error<<"Exception in main webserver thread: "<<e.reason<<endl;
  }
  catch(std::exception &e) {
    L<<Logger::Error<<"STL Exception in main webserver thread: "<<e.what()<<endl;
  }
  catch(...) {
    L<<Logger::Error<<"Unknown exception in main webserver thread"<<endl;
  }
  exit(1);

}
