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
#ifndef WEBSERVER_HH
#define WEBSERVER_HH
#include <map>
#include <string>
#include <list>
#include <boost/utility.hpp>
#include <yahttp/yahttp.hpp>
#include "json11.hpp"
#include "namespaces.hh"
#include "sstuff.hh"

class HttpRequest : public YaHTTP::Request {
public:
  HttpRequest(const string& logprefix_="") : YaHTTP::Request(), accept_json(false), accept_html(false), complete(false), logprefix(logprefix_) { };

  bool accept_json;
  bool accept_html;
  bool complete;
  string logprefix;
  json11::Json json();

  // checks password _only_.
  bool compareAuthorization(const string &expected_password);
  bool compareHeader(const string &header_name, const string &expected_value);
};

class HttpResponse: public YaHTTP::Response {
public:
  HttpResponse() : YaHTTP::Response() { };
  HttpResponse(const YaHTTP::Response &resp) : YaHTTP::Response(resp) { };

  void setBody(const json11::Json& document);
  void setErrorResult(const std::string& message, const int status);
  void setSuccessResult(const std::string& message, const int status = 200);
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
  ApiException(const string& what) : runtime_error(what) {
  }
};

class Server
{
public:
  Server(const string &localaddress, int port) : d_local(localaddress.empty() ? "0.0.0.0" : localaddress, port), d_server_socket(d_local.sin4.sin_family, SOCK_STREAM, 0) {
    d_server_socket.setReuseAddr();
    d_server_socket.bind(d_local);
    d_server_socket.listen();
  }
  virtual ~Server() { };

  ComboAddress d_local;

  std::shared_ptr<Socket> accept() {
    return std::shared_ptr<Socket>(d_server_socket.accept());
  }

protected:
  Socket d_server_socket;
};

class WebServer : public boost::noncopyable
{
public:
  WebServer(const string &listenaddress, int port);
  virtual ~WebServer() { };

  void setApiKey(const string &apikey) {
    d_apikey = apikey;
  }

  void setPassword(const string &password) {
    d_webserverPassword = password;
  }

  void setMaxBodySize(ssize_t s) { // in megabytes
    d_maxbodysize = s * 1024 * 1024;
  }

  void setACL(const NetmaskGroup &nmg) {
    d_acl = nmg;
  }

  void bind();
  void go();

  void serveConnection(std::shared_ptr<Socket> client) const;
  void handleRequest(HttpRequest& request, HttpResponse& resp) const;

  typedef boost::function<void(HttpRequest* req, HttpResponse* resp)> HandlerFunction;
  void registerApiHandler(const string& url, HandlerFunction handler, bool allowPassword=false);
  void registerWebHandler(const string& url, HandlerFunction handler);

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

protected:
  void registerBareHandler(const string& url, HandlerFunction handler);
  void logRequest(const HttpRequest& req, const ComboAddress& remote) const;
  void logResponse(const HttpResponse& resp, const ComboAddress& remote, const string& logprefix) const;

  virtual std::shared_ptr<Server> createServer() {
    return std::make_shared<Server>(d_listenaddress, d_port);
  }

  string d_listenaddress;
  int d_port;
  string d_password;
  std::shared_ptr<Server> d_server;

  std::string d_apikey;
  void apiWrapper(WebServer::HandlerFunction handler, HttpRequest* req, HttpResponse* resp, bool allowPassword);
  std::string d_webserverPassword;
  void webWrapper(WebServer::HandlerFunction handler, HttpRequest* req, HttpResponse* resp);

  ssize_t d_maxbodysize; // in bytes

  NetmaskGroup d_acl;

  const string d_logprefix = "[webserver] ";

  // Describes the amount of logging the webserver does
  WebServer::LogLevel d_loglevel{WebServer::LogLevel::Detailed};
};

#endif /* WEBSERVER_HH */
