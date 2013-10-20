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

struct connectionThreadData {
  WebServer* webServer;
  Session* client;
};

int WebServer::B64Decode(const std::string& strInput, std::string& strOutput)
{
  return ::B64Decode(strInput, strOutput);
}

// url is supposed to start with a slash.
// url can contain variable names, marked as <variable>; such variables
// are parsed out during routing and are put into the "pathArgs" map.
// route() makes no assumptions about the contents of variables except
// that the following URL segment can't be part of the variable.
//
// Examples:
//   registerHandler("/", &index);
//   registerHandler("/foo", &foo);
//   registerHandler("/foo/<bar>/<baz>", &foobarbaz);
void WebServer::registerHandler(const string& url, HandlerFunction handler)
{
  std::size_t pos = 0, lastpos = 0;

  HandlerRegistration reg;
  while ((pos = url.find('<', lastpos)) != std::string::npos) {
    std::string part = url.substr(lastpos, pos-lastpos);
    lastpos = pos;
    pos = url.find('>', pos);

    if (pos == std::string::npos) {
      throw std::logic_error("invalid url given");
    }

    std::string paramName = url.substr(lastpos+1, pos-lastpos-1);
    lastpos = pos+1;

    reg.urlParts.push_back(part);
    reg.paramNames.push_back(paramName);
  }
  std::string remainder = url.substr(lastpos);
  if (!remainder.empty()) {
    reg.urlParts.push_back(remainder);
    reg.paramNames.push_back("");
  }
  reg.handler = handler;
  d_handlers.push_back(reg);
}

bool WebServer::route(const std::string& url, std::map<std::string, std::string>& pathArgs, HandlerFunction** handler)
{
  for (std::list<HandlerRegistration>::iterator reg=d_handlers.begin(); reg != d_handlers.end(); ++reg) {
    bool matches = true;
    size_t lastpos = 0, pos = 0;
    string lastParam;
    pathArgs.clear();
    for (std::list<string>::iterator urlPart = reg->urlParts.begin(), param = reg->paramNames.begin();
         urlPart != reg->urlParts.end() && param != reg->paramNames.end();
         urlPart++, param++) {
      if (!urlPart->empty()) {
        pos = url.find(*urlPart, lastpos);
        if (pos == std::string::npos) {
          matches = false;
          break;
        }
        if (!lastParam.empty()) {
          // store
          pathArgs[lastParam] = url.substr(lastpos, pos-lastpos);
        }
        lastpos = pos + urlPart->size();
        lastParam = *param;
      }
    }
    if (matches) {
      if (!lastParam.empty()) {
        // store trailing parameter
        pathArgs[lastParam] = url.substr(lastpos, pos-lastpos);
      } else if (lastpos != url.size()) {
        matches = false;
        continue;
      }

      *handler = &reg->handler;
      return true;
    }
  }
  return false;
}

static void *WebServerConnectionThreadStart(void *p) {
  connectionThreadData* data = static_cast<connectionThreadData*>(p);
  pthread_detach(pthread_self());
  data->webServer->serveConnection(data->client);
  delete data;
  return NULL;
}

void WebServer::serveConnection(Session* client)
try {
  HttpRequest req;

  try {
    string line;
    client->setTimeout(5);
    client->getLine(line);
    stripLine(line);
    if(line.empty())
      throw HttpBadRequestException();
    //    L<<"page: "<<line<<endl;

    vector<string> parts;
    stringtok(parts, line);

    if(parts.size()>1) {
      req.method = parts[0];
      req.uri = parts[1];
    }

    parts.clear();
    stringtok(parts,req.uri,"?");
    req.path = parts[0];

    vector<string> variables;
    if(parts.size()>1) {
      stringtok(variables,parts[1],"&");
    }

    for(vector<string>::const_iterator i=variables.begin();
        i!=variables.end();++i) {

      parts.clear();
      stringtok(parts,*i,"=");
      if(parts.size()>1)
        req.queryArgs[parts[0]]=parts[1];
      else
        req.queryArgs[parts[0]]="";
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
      else if(header == "content-length" && req.method=="POST") {
        postlen = atoi(value.c_str());
//        cout<<"Got a post: "<<postlen<<" bytes"<<endl;
      }
      else if(header == "accept") {
        // json wins over html
        if(value.find("application/json")!=std::string::npos) {
          req.accept_json=true;
        } else if(value.find("text/html")!=std::string::npos) {
          req.accept_html=true;
        }
      }
      else
        ; // cerr<<"Ignoring line: "<<line<<endl;
      
    } while(true);

    if(postlen) 
      req.body = client->get(postlen);
  
    if(!d_password.empty() && !authOK)
      throw HttpUnauthorizedException();

    HandlerFunction *handler;
    if (route(req.path, req.pathArgs, &handler)) {
      bool custom=false;
      string ret=(*handler)(&req, &custom);

      if(!custom) {
        client->putLine("HTTP/1.1 200 OK\n");
        client->putLine("Connection: close\n");
        client->putLine("Content-Type: text/html; charset=utf-8\n\n");
      }
      client->putLine(ret);
    } else {
      throw HttpNotFoundException();
    }

  }
  catch(HttpException &e) {
    client->putLine(e.statusLine());
    client->putLine("Connection: close\n");
    client->putLine(e.headers());
    if(req.accept_html) {
      client->putLine("Content-Type: text/html; charset=utf-8\n\n");
      client->putLine("<!html><title>" + e.what() + "</title><h1>" + e.what() + "</h1>");
    } else if (req.accept_json) {
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
}
catch(SessionTimeoutException &e) {
  // L<<Logger::Error<<"Timeout in webserver"<<endl;
  return 0;
}
catch(PDNSException &e) {
  L<<Logger::Error<<"Exception in webserver: "<<e.reason<<endl;
  return 0;
}
catch(std::exception &e) {
  L<<Logger::Error<<"STL Exception in webserver: "<<e.what()<<endl;
  return 0;
}
catch(...) {
  L<<Logger::Error<<"Unknown exception in webserver"<<endl;
  return 0;
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
      // will be freed by thread
      connectionThreadData *data = new connectionThreadData;
      data->webServer = this;
      data->client = client;
      pthread_create(&tid, 0, &WebServerConnectionThreadStart, (void *)data);
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
