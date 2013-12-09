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

  data->client->close();
  delete data->client;

  delete data;

  return NULL;
}

HttpResponse WebServer::handleRequest(HttpRequest req)
{
  HttpResponse resp(req);
  // set default headers
  resp.headers["Content-Type"] = "text/html; charset=utf-8";

  try {
    YaHTTP::strstr_map_t::iterator header;

    if ((header = req.headers.find("accept")) != req.headers.end()) {
      // json wins over html
      if (header->second.find("application/json") != std::string::npos) {
        req.accept_json = true;
      } else if (header->second.find("text/html") != std::string::npos) {
        req.accept_html = true;
      }
    }

    if (!d_password.empty()) {
      // validate password
      header = req.headers.find("authorization");
      bool auth_ok = false;
      if (header != req.headers.end() && toLower(header->second).find("basic ") == 0) {
        string cookie = header->second.substr(6);

        string plain;
        B64Decode(cookie, plain);

        vector<string> cparts;
        stringtok(cparts, plain, ":");

        // this gets rid of terminating zeros
        auth_ok = (cparts.size()==2 && (0==strcmp(cparts[1].c_str(), d_password.c_str())));
      }
      if (!auth_ok) {
        throw HttpUnauthorizedException();
      }
    }

    HandlerFunction *handler;
    if (!route(req.url.path, req.path_parameters, &handler)) {
      throw HttpNotFoundException();
    }

    (*handler)(&req, &resp);
  }
  catch(HttpException &e) {
    resp = e.response();
    string what = YaHTTP::Utility::status2text(resp.status);
    if(req.accept_html) {
      resp.headers["Content-Type"] = "text/html; charset=utf-8";
      resp.body = "<!html><title>" + what + "</title><h1>" + what + "</h1>";
    } else if (req.accept_json) {
      resp.headers["Content-Type"] = "application/json";
      resp.body = returnJSONError(what);
    } else {
      resp.headers["Content-Type"] = "text/plain; charset=utf-8";
      resp.body = what;
    }
  }

  // always set these headers
  resp.headers["Server"] = "PowerDNS/"VERSION;
  resp.headers["Connection"] = "close";

  return resp;
}

void WebServer::serveConnection(Session* client)
try {
  HttpRequest req;
  YaHTTP::AsyncRequestLoader yarl(&req);

  client->setTimeout(5);

  bool complete = false;
  try {
    while(client->good()) {
      int bytes;
      char buf[1024];
      bytes = client->read(buf, sizeof(buf));
      if (bytes) {
        string data = string(buf, bytes);
        if (yarl.feed(data)) {
          complete = true;
          break;
        }
      }
    }
  } catch (YaHTTP::ParseError &e) {
    complete = false;
  }

  if (!complete) {
    client->put("HTTP/1.0 400 Bad Request\r\nConnection: close\r\n\r\nYour Browser sent a request that this server failed to understand.\r\n");
    return;
  }

  HttpResponse resp = WebServer::handleRequest(req);
  ostringstream ss;
  resp.write(ss);
  client->put(ss.str());
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
  try {
    d_server = new Server(d_listenaddress, d_port);
  }
  catch(SessionException &e) {
    L<<Logger::Error<<"Fatal error in webserver: "<<e.reason<<endl;
    d_server = NULL;
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
