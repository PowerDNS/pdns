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

#include "config.h"

#include "utility.hh"
#include "webserver.hh"
#include "misc.hh"
#include <thread>
#include "threadname.hh"
#include <utility>
#include <vector>
#include "logger.hh"
#include <stdio.h>
#include "dns.hh"
#include "base64.hh"
#include "json.hh"
#include "uuid-utils.hh"
#include <yahttp/router.hpp>
#include <algorithm>
#include <bitset>
#include <unistd.h>
#include <filesystem>

namespace filesystem = std::filesystem;

json11::Json HttpRequest::json()
{
  string err;
  if(this->body.empty()) {
    SLOG(g_log<<Logger::Debug<<logprefix<<"JSON document expected in request body, but body was empty" << endl,
         d_slog->info(Logr::Debug, "JSON document expected in request body, but body was empty"));
    throw HttpBadRequestException();
  }
  json11::Json doc = json11::Json::parse(this->body, err);
  if (doc.is_null()) {
    SLOG(g_log<<Logger::Debug<<logprefix<<"parsing of JSON document failed:" << err << endl,
         d_slog->error(Logr::Debug, err, "parsing of JSON document failed"));
    throw HttpBadRequestException();
  }
  return doc;
}

bool HttpRequest::compareAuthorization(const CredentialsHolder& credentials) const
{
  // validate password
  auto header = headers.find("authorization");
  bool auth_ok = false;
  if (header != headers.end() && toLower(header->second).find("basic ") == 0) {
    string cookie = header->second.substr(6);

    string plain;
    B64Decode(cookie, plain);

    vector<string> cparts;
    stringtok(cparts, plain, ":");

    auth_ok = (cparts.size() == 2 && credentials.matches(cparts[1].c_str()));
  }
  return auth_ok;
}

bool HttpRequest::compareHeader(const string &header_name, const string &expected_value) const
{
  auto header = headers.find(header_name);
  if (header == headers.end()) {
    return false;
  }

  // this gets rid of terminating zeros
  return (0==strcmp(header->second.c_str(), expected_value.c_str()));
}

bool HttpRequest::compareHeader(const string &header_name, const CredentialsHolder& credentials) const
{
  auto header = headers.find(header_name);
  if (header == headers.end()) {
    return false;
  }

  return credentials.matches(header->second);
}

void HttpResponse::setPlainBody(const string& document)
{
  this->headers["Content-Type"] = "text/plain; charset=utf-8";

  this->body = document;
}

void HttpResponse::setYamlBody(const string& document)
{
  this->headers["Content-Type"] = "application/x-yaml";

  this->body = document;
}

void HttpResponse::setJsonBody(const string& document)
{
  this->headers["Content-Type"] = "application/json";

  this->body = document;
}

void HttpResponse::setJsonBody(const json11::Json& document)
{
  this->headers["Content-Type"] = "application/json";

  document.dump(this->body);
}

void HttpResponse::setErrorResult(const std::string& message, const int status_)
{
  setJsonBody(json11::Json::object { { "error", message } });
  this->status = status_;
}

void HttpResponse::setSuccessResult(const std::string& message, const int status_)
{
  setJsonBody(json11::Json::object { { "result", message } });
  this->status = status_;
}

#ifndef RUST_WS

static void bareHandlerWrapper(const WebServer::HandlerFunction& handler, YaHTTP::Request* req, YaHTTP::Response* resp)
{
  // wrapper to convert from YaHTTP::* to our subclasses
  handler(static_cast<HttpRequest*>(req), static_cast<HttpResponse*>(resp));
}

void WebServer::registerBareHandler(const string& url, const HandlerFunction& handler, const std::string& method)
{
  YaHTTP::THandlerFunction f = [=](YaHTTP::Request* req, YaHTTP::Response* resp){return bareHandlerWrapper(handler, req, resp);};
  YaHTTP::Router::Map(method, url, std::move(f));
}

void WebServer::apiWrapper(const WebServer::HandlerFunction& handler, HttpRequest* req, HttpResponse* resp, bool allowPassword) {
  resp->headers["access-control-allow-origin"] = "*";

  if (!d_apikey) {
    SLOG(g_log<<Logger::Error<<req->logprefix<<"HTTP API Request \"" << req->url.path << "\": Authentication failed, API Key missing in config" << endl,
         d_slog->info(Logr::Error, "Authentication failed, API Key missing in config", "urlpath", Logging::Loggable(req->url.path)));
    throw HttpUnauthorizedException("X-API-Key");
  }

  bool auth_ok = req->compareHeader("x-api-key", *d_apikey) || d_apikey->matches(req->getvars["api-key"]);

  if (!auth_ok && allowPassword) {
    if (d_webserverPassword) {
      auth_ok = req->compareAuthorization(*d_webserverPassword);
    } else {
      auth_ok = true;
    }
  }

  if (!auth_ok) {
    SLOG(g_log<<Logger::Error<<req->logprefix<<"HTTP Request \"" << req->url.path << "\": Authentication by API Key failed" << endl,
         d_slog->info(Logr::Error, "Authentication by API Key failed", "urlpath", Logging::Loggable(req->url.path)));
    throw HttpUnauthorizedException("X-API-Key");
  }

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

void WebServer::registerApiHandler(const string& url, const HandlerFunction& handler, const std::string& method, bool allowPassword) {
  auto f = [=](HttpRequest *req, HttpResponse* resp){apiWrapper(handler, req, resp, allowPassword);};
  registerBareHandler(url, f, method);
}

void WebServer::webWrapper(const WebServer::HandlerFunction& handler, HttpRequest* req, HttpResponse* resp) {
  if (d_webserverPassword) {
    bool auth_ok = req->compareAuthorization(*d_webserverPassword);
    if (!auth_ok) {
      SLOG(g_log<<Logger::Debug<<req->logprefix<<"HTTP Request \"" << req->url.path << "\": Web Authentication failed" << endl,
           d_slog->info(Logr::Debug, "HTTP Request: Web Authentication failed",  "urlpath",  Logging::Loggable(req->url.path)));
      throw HttpUnauthorizedException("Basic");
    }
  }

  handler(req, resp);
}

void WebServer::registerWebHandler(const string& url, const HandlerFunction& handler, const std::string& method) {
  auto f = [=](HttpRequest *req, HttpResponse *resp){webWrapper(handler, req, resp);};
  registerBareHandler(url, f, method);
}

static void* WebServerConnectionThreadStart(const WebServer* webServer, const std::shared_ptr<Socket>& client)
{
  setThreadName("rec/webhndlr");
  const std::string msg = "Exception while serving a connection in main webserver thread";
  try {
    webServer->serveConnection(client);
  }
  catch(PDNSException &e) {
    SLOG(g_log<<Logger::Error<<"PDNSException while serving a connection in main webserver thread: "<<e.reason<<endl,
         webServer->d_slog->error(Logr::Error, e.reason, msg, "exception", Logging::Loggable("PDNSException")));
  }
  catch(std::exception &e) {
    SLOG(g_log<<Logger::Error<<"STL Exception while serving a connection in main webserver thread: "<<e.what()<<endl,
         webServer->d_slog->error(Logr::Error, e.what(), msg, "exception", Logging::Loggable("std::exception")));
  }
  catch(...) {
    SLOG(g_log<<Logger::Error<<"Unknown exception while serving a connection in main webserver thread"<<endl,
         webServer->d_slog->info(Logr::Error, msg));
  }
  return nullptr;
}

void WebServer::handleRequest(HttpRequest& req, HttpResponse& resp) const
{
  // set default headers
  resp.headers["Content-Type"] = "text/html; charset=utf-8";

#ifdef RECURSOR
    auto log = req.d_slog->withValues("urlpath", Logging::Loggable(req.url.path));
#endif

  try {
    if (!req.complete) {
      SLOG(g_log<<Logger::Debug<<req.logprefix<<"Incomplete request" << endl,
           d_slog->info(Logr::Debug, "Incomplete request"));
      throw HttpBadRequestException();
    }
    SLOG(g_log<<Logger::Debug<<req.logprefix<<"Handling request \"" << req.url.path << "\"" << endl,
         log->info(Logr::Debug, "Handling request"));

    YaHTTP::strstr_map_t::iterator header;

    if ((header = req.headers.find("accept")) != req.headers.end()) {
      // yaml wins over json, json wins over html
      if (header->second.find("application/x-yaml") != std::string::npos) {
        req.accept_yaml = true;
      } else if (header->second.find("text/x-yaml") != std::string::npos) {
        req.accept_yaml = true;
      } else if (header->second.find("application/json") != std::string::npos) {
        req.accept_json = true;
      } else if (header->second.find("text/html") != std::string::npos) {
        req.accept_html = true;
      }
    }

    YaHTTP::THandlerFunction handler;
    YaHTTP::RoutingResult res = YaHTTP::Router::Route(&req, handler);

    if (res == YaHTTP::RouteNotFound) {
      SLOG(g_log<<Logger::Debug<<req.logprefix<<"No route found for \"" << req.url.path << "\"" << endl,
           log->info(Logr::Debug, "No route found"));
      throw HttpNotFoundException();
    }
    if (res == YaHTTP::RouteNoMethod) {
      throw HttpMethodNotAllowedException();
    }

    const string msg = "HTTP ISE Exception";
    try {
      handler(&req, &resp);
      SLOG(g_log<<Logger::Debug<<req.logprefix<<"Result for \"" << req.url.path << "\": " << resp.status << ", body length: " << resp.body.size() << endl,
           log->info(Logr::Debug, "Result", "status", Logging::Loggable(resp.status), "bodyLength", Logging::Loggable(resp.body.size())));
    }
    catch(HttpException&) {
      throw;
    }
    catch(PDNSException &e) {
      SLOG(g_log<<Logger::Error<<req.logprefix<<"HTTP ISE for \""<< req.url.path << "\": Exception: " << e.reason << endl,
           log->error(Logr::Error, e.reason, msg, "exception", Logging::Loggable("PDNSException")));
      throw HttpInternalServerErrorException(e.reason);
    }
    catch(std::exception &e) {
      SLOG(g_log<<Logger::Error<<req.logprefix<<"HTTP ISE for \""<< req.url.path << "\": STL Exception: " << e.what() << endl,
           log->error(Logr::Error, e.what(), msg, "exception", Logging::Loggable("std::exception")));
      throw HttpInternalServerErrorException(e.what());
    }
    catch(...) {
      SLOG(g_log<<Logger::Error<<req.logprefix<<"HTTP ISE for \""<< req.url.path << "\": Unknown Exception" << endl,
           log->info(Logr::Error, msg));
      throw HttpInternalServerErrorException();
    }
  }
  catch(HttpException &e) {
    resp = e.response();
#ifdef RECURSOR
    // An HttpException does not initialize d_slog
    if (!resp.d_slog) {
      resp.setSLog(log);
    }
#endif
    // TODO rm this logline?
    SLOG(g_log<<Logger::Debug<<req.logprefix<<"Error result for \"" << req.url.path << "\": " << resp.status << endl,
         d_slog->error(Logr::Debug, resp.status, "Error result", "urlpath", Logging::Loggable(req.url.path)));
    string what = YaHTTP::Utility::status2text(resp.status);
    if (req.accept_json) {
      resp.headers["Content-Type"] = "application/json";
      if (resp.body.empty()) {
        resp.setErrorResult(what, resp.status);
      }
    } else if (req.accept_html) {
      resp.headers["Content-Type"] = "text/html; charset=utf-8";
      resp.body = "<!html><title>" + what + "</title><h1>" + what + "</h1>";
    } else {
      resp.headers["Content-Type"] = "text/plain; charset=utf-8";
      resp.body = std::move(what);
    }
  }

  // always set these headers
  resp.headers["Connection"] = "close";

  if (req.method == "HEAD") {
    resp.body = "";
  } else {
    resp.headers["Content-Length"] = std::to_string(resp.body.size());
  }
}

#ifdef RECURSOR
// Helper to log key-value maps used by YaHTTP
template<>
std::string Logging::IterLoggable<YaHTTP::strstr_map_t::const_iterator>::to_string() const
{
  std::ostringstream oss;
  bool first = true;
  for (auto i = _t1; i != _t2; i++) {
    if (!first) {
      oss << '\n';
    }
    else {
      first = false;
    }
    oss << i->first << ": " << i->second;
  }
  return oss.str();
}
#endif

void WebServer::logRequest(const HttpRequest& req, [[maybe_unused]] const ComboAddress& remote) const {
  if (d_loglevel >= WebServer::LogLevel::Detailed) {
#ifdef RECURSOR
    if (!g_slogStructured) {
#endif
      const auto& logprefix = req.logprefix;
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
#ifdef RECURSOR
    }
    else {
      req.d_slog->info(Logr::Info, "Request details", "getParams", Logging::IterLoggable(req.getvars.cbegin(), req.getvars.cend()),
                       "postParams", Logging::IterLoggable(req.postvars.cbegin(), req.postvars.cend()),
                       "body", Logging::Loggable(req.body),
                       "address", Logging::Loggable(remote));
    }
#endif
  }
}

void WebServer::logResponse(const HttpResponse& resp, const ComboAddress& /* remote */, const string& logprefix) const {
  if (d_loglevel >= WebServer::LogLevel::Detailed) {
#ifdef RECURSOR
    if (!g_slogStructured) {
#endif
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
#ifdef RECURSOR
    }
    else {
      resp.d_slog->info(Logr::Info, "Response details", "headers", Logging::IterLoggable(resp.headers.cbegin(), resp.headers.cend()),
                        "body", Logging::Loggable(resp.body));
    }
#endif
  }
}


struct ValidChars {
  ValidChars()
  {
    // letter may be signed, but we only pass positive values
    for (auto letter : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=") {
      set.set(letter);
    }
  }
  std::bitset<127> set;
};

static const ValidChars validChars;

static bool validURLChars(const string& str)
{
  for (auto iter = str.begin(); iter != str.end(); ++iter) {
    if (*iter == '%') {
      ++iter;
      if (iter == str.end() || isxdigit(static_cast<unsigned char>(*iter)) == 0) {
        return false;
      }
      ++iter;
      if (iter == str.end() || isxdigit(static_cast<unsigned char>(*iter)) == 0) {
        return false;
      }
    }
    else if (static_cast<size_t>(*iter) >= validChars.set.size() || !validChars.set[*iter]) {
      return false;
    }
  }
  return true;
}

bool WebServer::validURL(const YaHTTP::URL& url)
{
  bool isOK = true;
  isOK = isOK && validURLChars(url.protocol);
  isOK = isOK && validURLChars(url.host);
  isOK = isOK && validURLChars(url.username);
  isOK = isOK && validURLChars(url.password);
  isOK = isOK && validURLChars(url.path);
  isOK = isOK && validURLChars(url.parameters);
  isOK = isOK && validURLChars(url.anchor);
  return isOK;
}

void WebServer::serveConnection(const std::shared_ptr<Socket>& client) const {
  const auto unique = getUniqueID();
  const string logprefix = d_logprefix + to_string(unique) + " ";

  HttpRequest req(logprefix);

  HttpResponse resp;
#ifdef RECURSOR
  auto log = d_slog->withValues("uniqueid",  Logging::Loggable(to_string(unique)));
  req.setSLog(log);
  resp.setSLog(log);
#endif
  resp.max_response_size=d_maxbodysize;
  ComboAddress remote;
  string reply;

  try {
    YaHTTP::AsyncRequestLoader yarl;
    yarl.initialize(&req);
    req.max_request_size=d_maxbodysize;
    int timeout = d_connectiontimeout;
    client->setNonBlocking();

    try {
      while(!req.complete) {
        std::array<char, 16000> buf{};
        auto bytes = client->readWithTimeout(buf.data(), buf.size(), timeout);
        if (bytes > 0) {
          string data = string(buf.data(), bytes);
          req.complete = yarl.feed(data);
        } else {
          // read error OR EOF
          break;
        }
      }
      yarl.finalize();
    } catch (YaHTTP::ParseError &e) {
      // request stays incomplete
      SLOG(g_log<<Logger::Warning<<logprefix<<"Unable to parse request: "<<e.what()<<endl,
           d_slog->error(Logr::Warning, e.what(), "Unable to parse request"));
    }

    if (!validURL(req.url)) {
      throw PDNSException("Received request with invalid URL");
    }
    // Uses of `remote` below guarded by d_loglevel
    if (d_loglevel > WebServer::LogLevel::None) {
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
    SLOG(g_log<<Logger::Error<<logprefix<<"HTTP Exception: "<<e.reason<<endl,
         d_slog->error(Logr::Error, e.reason, "HTTP Exception", "exception", Logging::Loggable("PDNSException")));
  }
  catch(std::exception &e) {
    if(strstr(e.what(), "timeout")==nullptr)
      SLOG(g_log<<Logger::Error<<logprefix<<"HTTP STL Exception: "<<e.what()<<endl,
           d_slog->error(Logr::Error, e.what(), "HTTP Exception", "exception", Logging::Loggable("std::exception")));
  }
  catch(...) {
    SLOG(g_log<<Logger::Error<<logprefix<<"Unknown exception"<<endl,
         d_slog->info(Logr::Error, "HTTP Exception"));
  }

  if (d_loglevel >= WebServer::LogLevel::Normal) {
    SLOG(g_log<<Logger::Notice<<logprefix<<remote<<" \""<<req.method<<" "<<req.url.path<<" HTTP/"<<req.versionStr(req.version)<<"\" "<<resp.status<<" "<<reply.size()<<endl,
         d_slog->info(Logr::Info, "Request", "remote", Logging::Loggable(remote), "method", Logging::Loggable(req.method),
                      "urlpath", Logging::Loggable(req.url.path), "HTTPVersion", Logging::Loggable(req.versionStr(req.version)),
                      "status", Logging::Loggable(resp.status), "respsize",  Logging::Loggable(reply.size())));
  }
}

WebServer::WebServer(string listenaddress, int port) :
  d_listenaddress(std::move(listenaddress)),
  d_port(port),
  d_server(nullptr),
  d_maxbodysize(static_cast<ssize_t>(2 * 1024 * 1024))

{
    YaHTTP::Router::Map("OPTIONS", "/<*url>", [](YaHTTP::Request *req, YaHTTP::Response *resp) {
      // look for url in routes
      bool seen = false;
      std::vector<std::string> methods;
      for(const auto& route: YaHTTP::Router::GetRoutes()) {
         const auto& method = std::get<0>(route);
         const auto& url = std::get<1>(route);
         if (method == "OPTIONS") {
            continue;
         }
         std::map<std::string, YaHTTP::TDelim> params;
         if (YaHTTP::Router::Match(url, req->url, params)) {
            methods.push_back(method);
            seen = true;
         }
       }
       if (!seen) {
          resp->status = 404;
          resp->body = "";
          return;
       }
       methods.emplace_back("OPTIONS");
       resp->headers["access-control-allow-origin"] = "*";
       resp->headers["access-control-allow-headers"] = "Content-Type, X-API-Key";
       resp->headers["access-control-allow-methods"] = boost::algorithm::join(methods, ", ");
       resp->headers["access-control-max-age"] = "3600";
       resp->status = 200;
       resp->headers["content-type"]= "text/plain";
       resp->body = "";
    }, "OptionsHandlerRoute");
}

void WebServer::bind()
{
  if (filesystem::is_socket(d_listenaddress.c_str())) {
    int err=unlink(d_listenaddress.c_str());
    if(err < 0 && errno!=ENOENT) {
      SLOG(g_log<<Logger::Error<<d_logprefix<<"Listening on HTTP socket failed, unable to remove existing socket at "<<d_listenaddress<<endl,
           d_slog->error(Logr::Error, e.what(), "Listening on HTTP socket failed, unable to remove existing socket", "exception", d_listenaddress));
      d_server = nullptr;
      return;
    }
  }

  try {
    d_server = createServer();
    if (d_server->d_local.isUnixSocket()) {
      SLOG(g_log<<Logger::Warning<<d_logprefix<<"Listening for HTTP requests on "<<d_listenaddress<<endl,
           d_slog->info(Logr::Info, "Listening for HTTP requests", "path", Logging::Loggable(d_listenaddress)));
    } else {
        SLOG(g_log<<Logger::Warning<<d_logprefix<<"Listening for HTTP requests on "<<d_server->d_local.toStringWithPort()<<endl,
             d_slog->info(Logr::Info, "Listening for HTTP requests", "address", Logging::Loggable(d_server->d_local)));
    }
  }
  catch(NetworkError &e) {
    SLOG(g_log<<Logger::Error<<d_logprefix<<"Listening on HTTP socket failed: "<<e.what()<<endl,
         d_slog->error(Logr::Error, e.what(), "Listening on HTTP socket failed", "exception", Logging::Loggable("NetworkError")));
    d_server = nullptr;
  }
}

void WebServer::go()
{
  if(!d_server)
    return;
  const string msg = "Exception in main webserver thread";
  try {
    while(true) {
      const string acceptmsg = "Exception while accepting a connection in main webserver thread";
      try {
        auto client = d_server->accept();
        if (!client) {
          continue;
        }
        if (d_server->d_local.isUnixSocket() || client->acl(d_acl)) {
          std::thread webHandler(WebServerConnectionThreadStart, this, client);
          webHandler.detach();
        } else {
          ComboAddress remote;
          if (client->getRemote(remote))
            g_log<<Logger::Error<<d_logprefix<<"Webserver closing socket: remote ("<< remote.toString() <<") does not match the set ACL("<<d_acl.toString()<<")"<<endl;
        }
      }
      catch(PDNSException &e) {
        SLOG(g_log<<Logger::Error<<d_logprefix<<"PDNSException while accepting a connection in main webserver thread: "<<e.reason<<endl,
             d_slog->error(Logr::Error, e.reason, acceptmsg, Logging::Loggable("PDNSException")));
      }
      catch(std::exception &e) {
        SLOG(g_log<<Logger::Error<<d_logprefix<<"STL Exception while accepting a connection in main webserver thread: "<<e.what()<<endl,
             d_slog->error(Logr::Error, e.what(), acceptmsg, Logging::Loggable("std::exception")));
      }
      catch(...) {
        SLOG(g_log<<Logger::Error<<d_logprefix<<"Unknown exception while accepting a connection in main webserver thread"<<endl,
             d_slog->info(Logr::Error, msg));
      }
    }
  }
  catch(PDNSException &e) {
    SLOG(g_log<<Logger::Error<<d_logprefix<<"PDNSException in main webserver thread: "<<e.reason<<endl,
         d_slog->error(Logr::Error, e.reason, msg, Logging::Loggable("PDNSException")));
  }
  catch(std::exception &e) {
    SLOG(g_log<<Logger::Error<<d_logprefix<<"STL Exception in main webserver thread: "<<e.what()<<endl,
         d_slog->error(Logr::Error, e.what(), msg, Logging::Loggable("std::exception")));
  }
  catch(...) {
    SLOG(g_log<<Logger::Error<<d_logprefix<<"Unknown exception in main webserver thread"<<endl,
         d_slog->info(Logr::Error, msg));
  }
  _exit(1);
}
#endif // !RUST_WS
