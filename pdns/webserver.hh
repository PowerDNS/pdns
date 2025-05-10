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
#pragma once

#include "config.h"

#ifdef RECURSOR
// Network facing/routing part of webserver is implemented in rust. We stil use a few classes from
// yahttp, but do not link to it.
#define RUST_WS
#endif

#include <boost/utility.hpp>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverloaded-virtual"
#include <utility>
#include <yahttp/yahttp.hpp>
#pragma GCC diagnostic pop

#include "json11.hpp"

#include "credentials.hh"
#include "namespaces.hh"
#ifndef REST_WS
#include "sstuff.hh"
#endif
#include "logging.hh"

class HttpRequest : public YaHTTP::Request {
public:
  HttpRequest(string logprefix_ = "") :
    YaHTTP::Request(), logprefix(std::move(logprefix_)) {};

  string logprefix;
  bool accept_yaml{false};
  bool accept_json{false};
  bool accept_html{false};
  bool complete{false};

  json11::Json json();

  // checks password _only_.
  bool compareAuthorization(const CredentialsHolder& expectedCredentials) const;
  bool compareHeader(const string &header_name, const CredentialsHolder& expectedCredentials) const;
  bool compareHeader(const string &header_name, const string &expected_value) const;

#ifdef RECURSOR
  void setSLog(Logr::log_t log)
  {
    d_slog = log;
  }
  std::shared_ptr<Logr::Logger> d_slog;
#endif
};

class HttpResponse: public YaHTTP::Response {
public:
  HttpResponse() : YaHTTP::Response() { };
  HttpResponse(const YaHTTP::Response &resp) : YaHTTP::Response(resp) { };

  void setPlainBody(const string& document);
  void setYamlBody(const string& document);
  void setJsonBody(const string& document);
  void setJsonBody(const json11::Json& document);
  void setErrorResult(const std::string& message, const int status);
  void setSuccessResult(const std::string& message, const int status = 200);

#ifdef RECURSOR
  void setSLog(Logr::log_t log)
  {
    d_slog = log;
  }
  std::shared_ptr<Logr::Logger> d_slog;
#endif
};


class HttpException
{
public:
  HttpException(int status) : d_response()
  {
    d_response.status = status;
  };

  HttpException(int status, const string& msg) : d_response()
  {
    d_response.setErrorResult(msg, status);
  };

  HttpResponse response()
  {
    return d_response;
  }

protected:
  HttpResponse d_response;
};

class HttpBadRequestException : public HttpException {
public:
  HttpBadRequestException() : HttpException(400) { };
  HttpBadRequestException(const string& msg) : HttpException(400, msg) { };
};

class HttpUnauthorizedException : public HttpException {
public:
  HttpUnauthorizedException(string const &scheme) : HttpException(401)
  {
    d_response.headers["WWW-Authenticate"] = scheme + " realm=\"PowerDNS\"";
  }
};

class HttpForbiddenException : public HttpException {
public:
  HttpForbiddenException() : HttpException(403) { };
  HttpForbiddenException(const string& msg) : HttpException(403, msg) { };
};

class HttpNotFoundException : public HttpException {
public:
  HttpNotFoundException() : HttpException(404) { };
  HttpNotFoundException(const string& msg) : HttpException(404, msg) { };
};

class HttpMethodNotAllowedException : public HttpException {
public:
  HttpMethodNotAllowedException() : HttpException(405) { };
  HttpMethodNotAllowedException(const string& msg) : HttpException(405, msg) { };
};

class HttpConflictException : public HttpException {
public:
  HttpConflictException() : HttpException(409) { };
  HttpConflictException(const string& msg) : HttpException(409, msg) { };
};

class HttpInternalServerErrorException : public HttpException {
public:
  HttpInternalServerErrorException() : HttpException(500) { };
  HttpInternalServerErrorException(const string& msg) : HttpException(500, msg) { };
};

class ApiException : public runtime_error
{
public:
  ApiException(const string& what_arg) : runtime_error(what_arg) {
  }
};

#ifndef RUST_WS

class Server
{
public:
  Server(const string &localaddress, int port) : d_local(localaddress.empty() ? "0.0.0.0" : localaddress, port), d_server_socket(d_local.sin4.sin_family, SOCK_STREAM, 0) {
    d_server_socket.setReuseAddr();
    d_server_socket.bind(d_local);
    d_server_socket.listen();
  }
  Server(int server_socket) : d_local("fd:" + server_socket), d_server_socket(server_socket) {}
  virtual ~Server() = default;

  SockaddrWrapper d_local;

  std::shared_ptr<Socket> accept() {
    return std::shared_ptr<Socket>(d_server_socket.accept());
  }

protected:
  Socket d_server_socket;
};

class WebServer : public boost::noncopyable
{
public:
  WebServer(string listenaddress, int port);
  virtual ~WebServer() = default;

#ifdef RECURSOR
  void setSLog(Logr::log_t log)
  {
    d_slog = log;
  }
#endif

  void setApiKey(const string &apikey, bool hashPlaintext) {
    if (!apikey.empty()) {
      d_apikey = make_unique<CredentialsHolder>(std::string(apikey), hashPlaintext);
    }
    else {
      d_apikey.reset();
    }
  }

  void setPassword(const string &password, bool hashPlaintext) {
    if (!password.empty()) {
      d_webserverPassword = make_unique<CredentialsHolder>(std::string(password), hashPlaintext);
    }
    else {
      d_webserverPassword.reset();
    }
  }

  void setMaxBodySize(ssize_t s) { // in megabytes
    d_maxbodysize = s * 1024 * 1024;
  }

  void setConnectionTimeout(int t) { // in seconds
    d_connectiontimeout = t;
  }

  void setACL(const NetmaskGroup &nmg) {
    d_acl = nmg;
  }

  static bool validURL(const YaHTTP::URL& url);

  void bind();
  void go();

  void serveConnection(const std::shared_ptr<Socket>& client) const;
  void handleRequest(HttpRequest& request, HttpResponse& resp) const;

  typedef std::function<void(HttpRequest* req, HttpResponse* resp)> HandlerFunction;
  void registerApiHandler(const string& url, const HandlerFunction& handler, const std::string& method = "", bool allowPassword=false);
  void registerWebHandler(const string& url, const HandlerFunction& handler, const std::string& method = "");

  enum class LogLevel : uint8_t {
    None = 0,                // No logs from requests at all
    Normal = 10,             // A "common log format"-like line e.g. '127.0.0.1 "GET /apache_pb.gif HTTP/1.0" 200 2326'
    Detailed = 20,           // The full request headers and body, and the full response headers and body
  };

  void setLogLevel(const string& level) {
    if (level == "none") {
      d_loglevel = LogLevel::None;
      return;
    }

    if (level == "normal") {
      d_loglevel = LogLevel::Normal;
      return;
    }

    if (level == "detailed") {
      d_loglevel = LogLevel::Detailed;
      return;
    }

    throw PDNSException("Unknown webserver log level: " + level);
  }

  void setLogLevel(const LogLevel level) {
    d_loglevel = level;
  };

  LogLevel getLogLevel() {
    return d_loglevel;
  };

#ifdef RECURSOR
  std::shared_ptr<Logr::Logger> d_slog;
#endif

protected:
  static void registerBareHandler(const string& url, const HandlerFunction& handler, const std::string& method);
  void logRequest(const HttpRequest& req, const ComboAddress& remote) const;
  void logResponse(const HttpResponse& resp, const ComboAddress& remote, const string& logprefix) const;

  virtual std::shared_ptr<Server> createServer() {
    if (d_listenaddress.find("fd:") == 0) {
      int fd = std::stoi(d_listenaddress.substr(3, d_listenaddress.length()));
      return std::make_shared<Server>(fd);
    } else {
      return std::make_shared<Server>(d_listenaddress, d_port);
    }
  }

  void apiWrapper(const WebServer::HandlerFunction& handler, HttpRequest* req, HttpResponse* resp, bool allowPassword);
  void webWrapper(const WebServer::HandlerFunction& handler, HttpRequest* req, HttpResponse* resp);

  string d_listenaddress;
  int d_port;
  std::shared_ptr<Server> d_server;

  std::unique_ptr<CredentialsHolder> d_apikey{nullptr};
  std::unique_ptr<CredentialsHolder> d_webserverPassword{nullptr};

  ssize_t d_maxbodysize; // in bytes
  int d_connectiontimeout{5}; // in seconds

  NetmaskGroup d_acl;

  const string d_logprefix = "[webserver] ";

  // Describes the amount of logging the webserver does
  WebServer::LogLevel d_loglevel{WebServer::LogLevel::Detailed};
};

#endif // !RUST_WS
