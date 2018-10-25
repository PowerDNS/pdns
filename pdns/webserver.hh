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

class WebServer;

class HttpRequest : public YaHTTP::Request {
public:
  HttpRequest() : YaHTTP::Request(), accept_json(false), accept_html(false), complete(false) { };

  bool accept_json;
  bool accept_html;
  bool complete;
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
  void setErrorResult(const std::string& code, const std::string& message, const int status);
  void setSuccessResult(const std::string& message, const int status = 200);
};


class HttpException
{
public:
  HttpException(int status) : d_response()
  {
    d_response.status = status;
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
};

class HttpNotFoundException : public HttpException {
public:
  HttpNotFoundException() : HttpException(404) { };
};

class HttpMethodNotAllowedException : public HttpException {
public:
  HttpMethodNotAllowedException() : HttpException(405) { };
};

class HttpConflictException : public HttpException {
public:
  HttpConflictException() : HttpException(409) { };
};

class HttpInternalServerErrorException : public HttpException {
public:
  HttpInternalServerErrorException() : HttpException(500) { };
};

class ApiException : public runtime_error
{
public:
  ApiException(const char* code, const string& what) : runtime_error(what) {
      this->code = code;
  }
  ApiException(const char* code, const string& what, int statusCode) : runtime_error(what) {
      this->code = code;
      this->statusCode = statusCode;
  }

  const char* code;
  int statusCode = 422;

  // Pre-defined error codes
  static constexpr const char* ErrMethodNotAllowed  = "ERR_HTTP_METHOD_NOT_ALLOWED";
  static constexpr const char* ErrNotFound          = "ERR_NOT_FOUND";
  static constexpr const char* ErrBadRequest        = "ERR_BAD_REQUEST";
  static constexpr const char* ErrUnathorized       = "ERR_UNAUTHORIZED";
  static constexpr const char* ErrInternalError     = "ERR_INTERNAL_SERVER_ERROR";
  static constexpr const char* ErrGenericError      = "ERR_GENERIC_ERROR";
  static constexpr const char* ErrInvalidConfig     = "ERR_INVALID_CONFIGURATION";
  static constexpr const char* ErrIOError           = "ERR_IO_ERROR";
  static constexpr const char* ErrInvalidInput      = "ERR_INVALID_INPUT";
  static constexpr const char* ErrOPFailed          = "ERR_OP_FAIELD";
  static constexpr const char* ErrBadBackend        = "ERR_BAD_BACKEND";
  static constexpr const char* ErrSlaveZone         = "ERR_SLAVE_ZONE";
  static constexpr const char* ErrInvalidKind       = "ERR_INVALID_KIND";
  static constexpr const char* ErrNotFQDN           = "ERR_NOT_FQDN";
  static constexpr const char* ErrParsingError      = "ERR_PARSING_ERROR";
  static constexpr const char* ErrJSONError         = "ERR_JSON_ERROR";
  static constexpr const char* ErrMasterEmpty       = "ERR_MASTER_EMPTY";
  static constexpr const char* ErrRRGenericError    = "ERR_RR_GENERIC";
  static constexpr const char* ErrRRUnknownType     = "ERR_RR_UNKNOWN_TYPE";
  static constexpr const char* ErrRRNotInZone       = "ERR_RR_NOT_IN_ZONE";
  static constexpr const char* ErrRRAlreadyExists   = "ERR_RR_ALREADY_EXISTS";
  static constexpr const char* ErrRRConflict        = "ERR_RR_CONFLICT";
  static constexpr const char* ErrDomainNotSlave    = "ERR_DOMAIN_NOT_SLAVE";
  static constexpr const char* ErrZoneAlreadyExists = "ERR_ZONE_ALREADY_EXISTS";
  static constexpr const char* ErrZoneNotExists     = "ERR_ZONE_NOT_EXISRS";
  static constexpr const char* ErrZoneNotSigned     = "ERR_ZONE_NOT_SIGNED";
  static constexpr const char* ErrZoneNoRecord      = "ERR_ZONE_NO_RECORD";
  static constexpr const char* ErrSecGeneric        = "ERR_DNSSEC_GENERIC";
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
  void bind();
  void go();

  void serveConnection(std::shared_ptr<Socket> client) const;
  void handleRequest(HttpRequest& request, HttpResponse& resp) const;

  typedef boost::function<void(HttpRequest* req, HttpResponse* resp)> HandlerFunction;
  void registerApiHandler(const string& url, HandlerFunction handler);
  void registerWebHandler(const string& url, HandlerFunction handler);

protected:
  void registerBareHandler(const string& url, HandlerFunction handler);

  virtual std::shared_ptr<Server> createServer() {
    return std::make_shared<Server>(d_listenaddress, d_port);
  }

  string d_listenaddress;
  int d_port;
  string d_password;
  std::shared_ptr<Server> d_server;
};

#endif /* WEBSERVER_HH */
