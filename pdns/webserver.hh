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
#ifndef WEBSERVER_HH
#define WEBSERVER_HH
#include <map>
#include <string>
#include <list>
#include <boost/utility.hpp>
#include <yahttp/yahttp.hpp>
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "namespaces.hh"
#include "sstuff.hh"

class HttpRequest : public YaHTTP::Request {
public:
  HttpRequest() : YaHTTP::Request(), accept_json(false), accept_html(false), complete(false) { };

  bool accept_json;
  bool accept_html;
  bool complete;
  void json(rapidjson::Document& document);
};

class HttpResponse: public YaHTTP::Response {
public:
  HttpResponse() : YaHTTP::Response() { };
  HttpResponse(const YaHTTP::Response &resp) : YaHTTP::Response(resp) { };

  void setBody(rapidjson::Document& document);
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
  HttpUnauthorizedException() : HttpException(401)
  {
    d_response.headers["WWW-Authenticate"] = "Basic realm=\"PowerDNS\"";
  }
};

class HttpNotFoundException : public HttpException {
public:
  HttpNotFoundException() : HttpException(404) { };
};

class HttpMethodNotAllowedException : public HttpException {
public:
  HttpMethodNotAllowedException() : HttpException(405) { };
};

class HttpInternalServerErrorException : public HttpException {
public:
  HttpInternalServerErrorException() : HttpException(500) { };
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

  ComboAddress d_local;

  Socket *accept() {
    return d_server_socket.accept();
  }

protected:
  Socket d_server_socket;
};

class WebServer : public boost::noncopyable
{
public:
  WebServer(const string &listenaddress, int port, const string &password="");
  void bind();
  void go();

  void serveConnection(Socket *client);
  HttpResponse handleRequest(HttpRequest request);

  typedef boost::function<void(HttpRequest* req, HttpResponse* resp)> HandlerFunction;
  void registerHandler(const string& url, HandlerFunction handler);
  void registerApiHandler(const string& url, HandlerFunction handler);

protected:
  static char B64Decode1(char cInChar);
  static int B64Decode(const std::string& strInput, std::string& strOutput);

  virtual Server* createServer() {
    return new Server(d_listenaddress, d_port);
  }

  string d_listenaddress;
  int d_port;
  string d_password;
  Server* d_server;
};

#endif /* WEBSERVER_HH */
