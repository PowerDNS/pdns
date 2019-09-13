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
#include "utility.hh"
#include "webserver.hh"
#include "misc.hh"
#include <thread>
#include "threadname.hh"
#include <vector>
#include "logger.hh"
#include <stdio.h>
#include "dns.hh"
#include "base64.hh"
#include "json.hh"
#include "uuid-utils.hh"
#include <yahttp/router.hpp>

json11::Json HttpRequest::json()
{
  string err;
  if(this->body.empty()) {
    g_log<<Logger::Debug<<logprefix<<"JSON document expected in request body, but body was empty" << endl;
    throw HttpBadRequestException();
  }
  json11::Json doc = json11::Json::parse(this->body, err);
  if (doc.is_null()) {
    g_log<<Logger::Debug<<logprefix<<"parsing of JSON document failed:" << err << endl;
    throw HttpBadRequestException();
  }
  return doc;
}

bool HttpRequest::compareAuthorization(const string &expected_password)
{
  // validate password
  YaHTTP::strstr_map_t::iterator header = headers.find("authorization");
  bool auth_ok = false;
  if (header != headers.end() && toLower(header->second).find("basic ") == 0) {
    string cookie = header->second.substr(6);

    string plain;
    B64Decode(cookie, plain);

    vector<string> cparts;
    stringtok(cparts, plain, ":");

    // this gets rid of terminating zeros
    auth_ok = (cparts.size()==2 && (0==strcmp(cparts[1].c_str(), expected_password.c_str())));
  }
  return auth_ok;
}

bool HttpRequest::compareHeader(const string &header_name, const string &expected_value)
{
  YaHTTP::strstr_map_t::iterator header = headers.find(header_name);
  if (header == headers.end())
    return false;

  // this gets rid of terminating zeros
  return (0==strcmp(header->second.c_str(), expected_value.c_str()));
}


void HttpResponse::setBody(const json11::Json& document)
{
  document.dump(this->body);
}

void HttpResponse::setErrorResult(const std::string& message, const int status_)
{
  setBody(json11::Json::object { { "error", message } });
  this->status = status_;
}

void HttpResponse::setSuccessResult(const std::string& message, const int status_)
{
  setBody(json11::Json::object { { "result", message } });
  this->status = status_;
}

static void bareHandlerWrapper(WebServer::HandlerFunction handler, YaHTTP::Request* req, YaHTTP::Response* resp)
{
  // wrapper to convert from YaHTTP::* to our subclasses
  handler(static_cast<HttpRequest*>(req), static_cast<HttpResponse*>(resp));
}

void WebServer::registerBareHandler(const string& url, HandlerFunction handler)
{
  YaHTTP::THandlerFunction f = boost::bind(&bareHandlerWrapper, handler, _1, _2);
  YaHTTP::Router::Any(url, f);
}

static bool optionsHandler(HttpRequest* req, HttpResponse* resp) {
  if (req->method == "OPTIONS") {
    resp->headers["access-control-allow-origin"] = "*";
    resp->headers["access-control-allow-headers"] = "Content-Type, X-API-Key";
    resp->headers["access-control-allow-methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS";
    resp->headers["access-control-max-age"] = "3600";
    resp->status = 200;
    resp->headers["content-type"]= "text/plain";
    resp->body = "";
    return true;
  }
  return false;
}

void WebServer::apiWrapper(WebServer::HandlerFunction handler, HttpRequest* req, HttpResponse* resp, bool allowPassword) {
  if (optionsHandler(req, resp)) return;

  resp->headers["access-control-allow-origin"] = "*";

  if (d_apikey.empty()) {
    g_log<<Logger::Error<<req->logprefix<<"HTTP API Request \"" << req->url.path << "\": Authentication failed, API Key missing in config" << endl;
    throw HttpUnauthorizedException("X-API-Key");
  }

  bool auth_ok = req->compareHeader("x-api-key", d_apikey) || req->getvars["api-key"] == d_apikey;

  if (!auth_ok && allowPassword) {
    if (!d_webserverPassword.empty()) {
      auth_ok = req->compareAuthorization(d_webserverPassword);
    } else {
      auth_ok = true;
    }
  }

  if (!auth_ok) {
    g_log<<Logger::Error<<req->logprefix<<"HTTP Request \"" << req->url.path << "\": Authentication by API Key failed" << endl;
    throw HttpUnauthorizedException("X-API-Key");
  }

  resp->headers["Content-Type"] = "application/json";

  // security headers
  resp->headers["X-Content-Type-Options"] = "nosniff";
  resp->headers["X-Frame-Options"] = "deny";
  resp->headers["X-Permitted-Cross-Domain-Policies"] = "none";
  resp->headers["X-XSS-Protection"] = "1; mode=block";
  resp->headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'";

  req->getvars.erase("_"); // jQuery cache buster

  try {
    resp->status = 200;
    handler(req, resp);
  } catch (ApiException &e) {
    resp->setErrorResult(e.what(), 422);
    return;
  } catch (JsonException &e) {
    resp->setErrorResult(e.what(), 422);
    return;
  }

  if (resp->status == 204) {
    // No Content -> no Content-Type.
    resp->headers.erase("Content-Type");
  }
}

void WebServer::registerApiHandler(const string& url, HandlerFunction handler, bool allowPassword) {
  HandlerFunction f = boost::bind(&WebServer::apiWrapper, this, handler, _1, _2, allowPassword);
  registerBareHandler(url, f);
}

void WebServer::webWrapper(WebServer::HandlerFunction handler, HttpRequest* req, HttpResponse* resp) {
  if (!d_webserverPassword.empty()) {
    bool auth_ok = req->compareAuthorization(d_webserverPassword);
    if (!auth_ok) {
      g_log<<Logger::Debug<<req->logprefix<<"HTTP Request \"" << req->url.path << "\": Web Authentication failed" << endl;
      throw HttpUnauthorizedException("Basic");
    }
  }

  handler(req, resp);
}

void WebServer::registerWebHandler(const string& url, HandlerFunction handler) {
  HandlerFunction f = boost::bind(&WebServer::webWrapper, this, handler, _1, _2);
  registerBareHandler(url, f);
}

static void *WebServerConnectionThreadStart(const WebServer* webServer, std::shared_ptr<Socket> client) {
  setThreadName("pdns-r/webhndlr");
  try {
    webServer->serveConnection(client);
  }
  catch(PDNSException &e) {
    g_log<<Logger::Error<<"PDNSException while serving a connection in main webserver thread: "<<e.reason<<endl;
  }
  catch(std::exception &e) {
    g_log<<Logger::Error<<"STL Exception while serving a connection in main webserver thread: "<<e.what()<<endl;
  }
  catch(...) {
    g_log<<Logger::Error<<"Unknown exception while serving a connection in main webserver thread"<<endl;
  }
  return nullptr;
}

void WebServer::handleRequest(HttpRequest& req, HttpResponse& resp) const
{
  // set default headers
  resp.headers["Content-Type"] = "text/html; charset=utf-8";

  try {
    if (!req.complete) {
      g_log<<Logger::Debug<<req.logprefix<<"Incomplete request" << endl;
      throw HttpBadRequestException();
    }

    g_log<<Logger::Debug<<req.logprefix<<"Handling request \"" << req.url.path << "\"" << endl;

    YaHTTP::strstr_map_t::iterator header;

    if ((header = req.headers.find("accept")) != req.headers.end()) {
      // json wins over html
      if (header->second.find("application/json") != std::string::npos) {
        req.accept_json = true;
      } else if (header->second.find("text/html") != std::string::npos) {
        req.accept_html = true;
      }
    }

    YaHTTP::THandlerFunction handler;
    if (!YaHTTP::Router::Route(&req, handler)) {
      g_log<<Logger::Debug<<req.logprefix<<"No route found for \"" << req.url.path << "\"" << endl;
      throw HttpNotFoundException();
    }

    try {
      handler(&req, &resp);
      g_log<<Logger::Debug<<req.logprefix<<"Result for \"" << req.url.path << "\": " << resp.status << ", body length: " << resp.body.size() << endl;
    }
    catch(HttpException&) {
      throw;
    }
    catch(PDNSException &e) {
      g_log<<Logger::Error<<req.logprefix<<"HTTP ISE for \""<< req.url.path << "\": Exception: " << e.reason << endl;
      throw HttpInternalServerErrorException();
    }
    catch(std::exception &e) {
      g_log<<Logger::Error<<req.logprefix<<"HTTP ISE for \""<< req.url.path << "\": STL Exception: " << e.what() << endl;
      throw HttpInternalServerErrorException();
    }
    catch(...) {
      g_log<<Logger::Error<<req.logprefix<<"HTTP ISE for \""<< req.url.path << "\": Unknown Exception" << endl;
      throw HttpInternalServerErrorException();
    }
  }
  catch(HttpException &e) {
    resp = e.response();
    // TODO rm this logline?
    g_log<<Logger::Debug<<req.logprefix<<"Error result for \"" << req.url.path << "\": " << resp.status << endl;
    string what = YaHTTP::Utility::status2text(resp.status);
    if(req.accept_html) {
      resp.headers["Content-Type"] = "text/html; charset=utf-8";
      resp.body = "<!html><title>" + what + "</title><h1>" + what + "</h1>";
    } else if (req.accept_json) {
      resp.headers["Content-Type"] = "application/json";
      if (resp.body.empty()) {
        resp.setErrorResult(what, resp.status);
      }
    } else {
      resp.headers["Content-Type"] = "text/plain; charset=utf-8";
      resp.body = what;
    }
  }

  // always set these headers
  resp.headers["Server"] = "PowerDNS/" VERSION;
  resp.headers["Connection"] = "close";

  if (req.method == "HEAD") {
    resp.body = "";
  } else {
    resp.headers["Content-Length"] = std::to_string(resp.body.size());
  }
}

void WebServer::logRequest(const HttpRequest& req, const ComboAddress& remote) const {
  if (d_loglevel >= WebServer::LogLevel::Detailed) {
    auto logprefix = req.logprefix;
    g_log<<Logger::Notice<<logprefix<<"Request details:"<<endl;

    bool first = true;
    for (const auto& r : req.getvars) {
      if (first) {
        first = false;
        g_log<<Logger::Notice<<logprefix<<" GET params:"<<endl;
      }
      g_log<<Logger::Notice<<logprefix<<"  "<<r.first<<": "<<r.second<<endl;
    }

    first = true;
    for (const auto& r : req.postvars) {
      if (first) {
        first = false;
        g_log<<Logger::Notice<<logprefix<<" POST params:"<<endl;
      }
      g_log<<Logger::Notice<<logprefix<<"  "<<r.first<<": "<<r.second<<endl;
    }

    first = true;
    for (const auto& h : req.headers) {
      if (first) {
        first = false;
        g_log<<Logger::Notice<<logprefix<<" Headers:"<<endl;
      }
      g_log<<Logger::Notice<<logprefix<<"  "<<h.first<<": "<<h.second<<endl;
    }

    if (req.body.empty()) {
      g_log<<Logger::Notice<<logprefix<<" No body"<<endl;
    } else {
      g_log<<Logger::Notice<<logprefix<<" Full body: "<<endl;
      g_log<<Logger::Notice<<logprefix<<"  "<<req.body<<endl;
    }
  }
}

void WebServer::logResponse(const HttpResponse& resp, const ComboAddress& remote, const string& logprefix) const {
  if (d_loglevel >= WebServer::LogLevel::Detailed) {
    g_log<<Logger::Notice<<logprefix<<"Response details:"<<endl;
    bool first = true;
    for (const auto& h : resp.headers) {
      if (first) {
        first = false;
        g_log<<Logger::Notice<<logprefix<<" Headers:"<<endl;
      }
      g_log<<Logger::Notice<<logprefix<<"  "<<h.first<<": "<<h.second<<endl;
    }
    if (resp.body.empty()) {
      g_log<<Logger::Notice<<logprefix<<" No body"<<endl;
    } else {
      g_log<<Logger::Notice<<logprefix<<" Full body: "<<endl;
      g_log<<Logger::Notice<<logprefix<<"  "<<resp.body<<endl;
    }
  }
}

void WebServer::serveConnection(std::shared_ptr<Socket> client) const {
  const string logprefix = d_logprefix + to_string(getUniqueID()) + " ";

  HttpRequest req(logprefix);
  HttpResponse resp;
  resp.max_response_size=d_maxbodysize;
  ComboAddress remote;
  string reply;

  try {
    YaHTTP::AsyncRequestLoader yarl;
    yarl.initialize(&req);
    req.max_request_size=d_maxbodysize;
    int timeout = 5;
    client->setNonBlocking();

    try {
      while(!req.complete) {
        int bytes;
        char buf[16000];
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
      g_log<<Logger::Warning<<logprefix<<"Unable to parse request: "<<e.what()<<endl;
    }

    if (d_loglevel >= WebServer::LogLevel::None) {
      client->getRemote(remote);
    }

    logRequest(req, remote);

    WebServer::handleRequest(req, resp);
    ostringstream ss;
    resp.write(ss);
    reply = ss.str();

    logResponse(resp, remote, logprefix);

    client->writenWithTimeout(reply.c_str(), reply.size(), timeout);
  }
  catch(PDNSException &e) {
    g_log<<Logger::Error<<logprefix<<"HTTP Exception: "<<e.reason<<endl;
  }
  catch(std::exception &e) {
    if(strstr(e.what(), "timeout")==0)
      g_log<<Logger::Error<<logprefix<<"HTTP STL Exception: "<<e.what()<<endl;
  }
  catch(...) {
    g_log<<Logger::Error<<logprefix<<"Unknown exception"<<endl;
  }

  if (d_loglevel >= WebServer::LogLevel::Normal) {
    g_log<<Logger::Notice<<logprefix<<remote<<" \""<<req.method<<" "<<req.url.path<<" HTTP/"<<req.versionStr(req.version)<<"\" "<<resp.status<<" "<<reply.size()<<endl;
  }
}

WebServer::WebServer(const string &listenaddress, int port) :
  d_listenaddress(listenaddress),
  d_port(port),
  d_server(nullptr),
  d_maxbodysize(2*1024*1024)
{
}

void WebServer::bind()
{
  try {
    d_server = createServer();
    g_log<<Logger::Warning<<d_logprefix<<"Listening for HTTP requests on "<<d_server->d_local.toStringWithPort()<<endl;
  }
  catch(NetworkError &e) {
    g_log<<Logger::Error<<d_logprefix<<"Listening on HTTP socket failed: "<<e.what()<<endl;
    d_server = nullptr;
  }
}

void WebServer::go()
{
  if(!d_server)
    return;
  try {
    while(true) {
      try {
        auto client = d_server->accept();
        if (!client) {
          continue;
        }
        if (client->acl(d_acl)) {
          std::thread webHandler(WebServerConnectionThreadStart, this, client);
          webHandler.detach();
        } else {
          ComboAddress remote;
          if (client->getRemote(remote))
            g_log<<Logger::Error<<d_logprefix<<"Webserver closing socket: remote ("<< remote.toString() <<") does not match the set ACL("<<d_acl.toString()<<")"<<endl;
        }
      }
      catch(PDNSException &e) {
        g_log<<Logger::Error<<d_logprefix<<"PDNSException while accepting a connection in main webserver thread: "<<e.reason<<endl;
      }
      catch(std::exception &e) {
        g_log<<Logger::Error<<d_logprefix<<"STL Exception while accepting a connection in main webserver thread: "<<e.what()<<endl;
      }
      catch(...) {
        g_log<<Logger::Error<<d_logprefix<<"Unknown exception while accepting a connection in main webserver thread"<<endl;
      }
    }
  }
  catch(PDNSException &e) {
    g_log<<Logger::Error<<d_logprefix<<"PDNSException in main webserver thread: "<<e.reason<<endl;
  }
  catch(std::exception &e) {
    g_log<<Logger::Error<<d_logprefix<<"STL Exception in main webserver thread: "<<e.what()<<endl;
  }
  catch(...) {
    g_log<<Logger::Error<<d_logprefix<<"Unknown exception in main webserver thread"<<endl;
  }
  _exit(1);
}
