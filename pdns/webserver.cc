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
#include "misc.hh"
#include <vector>
#include "logger.hh"
#include <stdio.h>
#include "dns.hh"
#include "base64.hh"
#include "json.hh"
#include <yahttp/router.hpp>

struct connectionThreadData {
  WebServer* webServer;
  Socket* client;
};

void HttpRequest::json(rapidjson::Document& document)
{
  if(this->body.empty()) {
    L<<Logger::Debug<<"HTTP: JSON document expected in request body, but body was empty" << endl;
    throw HttpBadRequestException();
  }
  if(document.Parse<0>(this->body.c_str()).HasParseError()) {
    L<<Logger::Debug<<"HTTP: parsing of JSON document failed" << endl;
    throw HttpBadRequestException();
  }
}

void HttpResponse::setBody(rapidjson::Document& document)
{
  this->body = makeStringFromDocument(document);
}

int WebServer::B64Decode(const std::string& strInput, std::string& strOutput)
{
  return ::B64Decode(strInput, strOutput);
}

static void handlerWrapper(WebServer::HandlerFunction handler, YaHTTP::Request* req, YaHTTP::Response* resp)
{
  // wrapper to convert from YaHTTP::* to our subclasses
  handler(static_cast<HttpRequest*>(req), static_cast<HttpResponse*>(resp));
}

void WebServer::registerHandler(const string& url, HandlerFunction handler)
{
  YaHTTP::THandlerFunction f = boost::bind(&handlerWrapper, handler, _1, _2);
  YaHTTP::Router::Any(url, f);
}

static void apiWrapper(WebServer::HandlerFunction handler, HttpRequest* req, HttpResponse* resp) {
  resp->headers["Access-Control-Allow-Origin"] = "*";
  resp->headers["Content-Type"] = "application/json";

  string callback;

  if(req->getvars.count("callback")) {
    callback=req->getvars["callback"];
    req->getvars.erase("callback");
  }

  req->getvars.erase("_"); // jQuery cache buster

  try {
    resp->status = 200;
    handler(req, resp);
  } catch (ApiException &e) {
    resp->body = returnJsonError(e.what());
    resp->status = 422;
    return;
  } catch (JsonException &e) {
    resp->body = returnJsonError(e.what());
    resp->status = 422;
    return;
  }

  if (resp->status == 204) {
    // No Content -> no Content-Type.
    resp->headers.erase("Content-Type");
  }

  if(!callback.empty()) {
    resp->body = callback + "(" + resp->body + ");";
  }
}

void WebServer::registerApiHandler(const string& url, HandlerFunction handler) {
  HandlerFunction f = boost::bind(&apiWrapper, handler, _1, _2);
  registerHandler(url, f);
}

static void *WebServerConnectionThreadStart(void *p) {
  connectionThreadData* data = static_cast<connectionThreadData*>(p);
  pthread_detach(pthread_self());
  data->webServer->serveConnection(data->client);

  delete data->client; // close socket
  delete data;

  return NULL;
}

HttpResponse WebServer::handleRequest(HttpRequest req)
{
  HttpResponse resp;

  // set default headers
  resp.headers["Content-Type"] = "text/html; charset=utf-8";

  try {
    if (!req.complete) {
      L<<Logger::Debug<<"HTTP: Incomplete request" << endl;
      throw HttpBadRequestException();
    }

    L<<Logger::Debug<<"HTTP: Handling request \"" << req.url.path << "\"" << endl;

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
        L<<Logger::Debug<<"HTTP Request \"" << req.url.path << "\": Authentication failed" << endl;
        throw HttpUnauthorizedException();
      }
    }

    YaHTTP::THandlerFunction handler;
    if (!YaHTTP::Router::Route(&req, handler)) {
      L<<Logger::Debug<<"HTTP: No route found for \"" << req.url.path << "\"" << endl;
      throw HttpNotFoundException();
    }

    try {
      handler(&req, &resp);
      L<<Logger::Debug<<"HTTP: Result for \"" << req.url.path << "\": " << resp.status << ", body length: " << resp.body.size() << endl;
    }
    catch(HttpException) {
      throw;
    }
    catch(PDNSException &e) {
      L<<Logger::Error<<"HTTP ISE for \""<< req.url.path << "\": Exception: " << e.reason << endl;
      throw HttpInternalServerErrorException();
    }
    catch(std::exception &e) {
      L<<Logger::Error<<"HTTP ISE for \""<< req.url.path << "\": STL Exception: " << e.what() << endl;
      throw HttpInternalServerErrorException();
    }
    catch(...) {
      L<<Logger::Error<<"HTTP ISE for \""<< req.url.path << "\": Unknown Exception" << endl;
      throw HttpInternalServerErrorException();
    }
  }
  catch(HttpException &e) {
    resp = e.response();
    L<<Logger::Debug<<"HTTP: Error result for \"" << req.url.path << "\": " << resp.status << endl;
    string what = YaHTTP::Utility::status2text(resp.status);
    if(req.accept_html) {
      resp.headers["Content-Type"] = "text/html; charset=utf-8";
      resp.body = "<!html><title>" + what + "</title><h1>" + what + "</h1>";
    } else if (req.accept_json) {
      resp.headers["Content-Type"] = "application/json";
      resp.body = returnJsonError(what);
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

void WebServer::serveConnection(Socket *client)
try {
  HttpRequest req;
  YaHTTP::AsyncRequestLoader yarl;
  yarl.initialize(&req);
  int timeout = 5;
  client->setNonBlocking();

  try {
    while(!req.complete) {
      int bytes;
      char buf[1024];
      bytes = client->readWithTimeout(buf, sizeof(buf), timeout);
      if (bytes > 0) {
        string data = string(buf, bytes);
        req.complete = yarl.feed(data);
      } else {
        // read error OR EOF
        break;
      }
    }
    yarl.finalize();
  } catch (YaHTTP::ParseError &e) {
    // request stays incomplete
  }

  HttpResponse resp = WebServer::handleRequest(req);
  ostringstream ss;
  resp.write(ss);
  string reply = ss.str();

  client->writenWithTimeout(reply.c_str(), reply.size(), timeout);
}
catch(PDNSException &e) {
  L<<Logger::Error<<"HTTP Exception: "<<e.reason<<endl;
}
catch(std::exception &e) {
  L<<Logger::Error<<"HTTP STL Exception: "<<e.what()<<endl;
}
catch(...) {
  L<<Logger::Error<<"HTTP: Unknown exception"<<endl;
}

WebServer::WebServer(const string &listenaddress, int port, const string &password) : d_server(NULL)
{
  d_listenaddress=listenaddress;
  d_port=port;
  d_password=password;
}

void WebServer::bind()
{
  try {
    d_server = createServer();
    L<<Logger::Warning<<"Listening for HTTP requests on "<<d_server->d_local.toStringWithPort()<<endl;
  }
  catch(NetworkError &e) {
    L<<Logger::Error<<"Listening on HTTP socket failed: "<<e.what()<<endl;
    d_server = NULL;
  }
}

void WebServer::go()
{
  if(!d_server)
    return;
  try {
    pthread_t tid;

    while(true) {
      // data and data->client will be freed by thread
      connectionThreadData *data = new connectionThreadData;
      data->webServer = this;
      data->client = d_server->accept();
      pthread_create(&tid, 0, &WebServerConnectionThreadStart, (void *)data);
    }
  }
  catch(std::exception &e) {
    L<<Logger::Error<<"STL Exception in main webserver thread: "<<e.what()<<endl;
  }
  catch(...) {
    L<<Logger::Error<<"Unknown exception in main webserver thread"<<endl;
  }
  exit(1);
}
