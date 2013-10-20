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

#include "namespaces.hh"
class Server;
class Session;

class HttpException
{
public:
  HttpException(int status_code, const std::string& reason_phrase) :
    d_status_code(status_code), d_reason_phrase(reason_phrase)
  {
  };

  virtual std::string statusLine() const {
    return "HTTP/1.0 " + lexical_cast<string>(d_status_code) + " " + d_reason_phrase + "\n";
  }

  virtual std::string headers() const {
    return "";
  }

  virtual std::string what() const {
    return d_reason_phrase;
  }

private:
  int d_status_code;
  std::string d_reason_phrase;
};

class HttpBadRequestException : public HttpException {
public:
  HttpBadRequestException() : HttpException(400, "Bad Request") { };
};

class HttpUnauthorizedException : public HttpException {
public:
  HttpUnauthorizedException() : HttpException(401, "Unauthorized") { };

  std::string headers() const {
    return "WWW-Authenticate: Basic realm=\"PowerDNS\"\n";
  }
};

class HttpNotFoundException : public HttpException {
public:
  HttpNotFoundException() : HttpException(404, "Not Found") { };
};

class HttpMethodNotAllowedException : public HttpException {
public:
  HttpMethodNotAllowedException() : HttpException(405, "Method Not Allowed") { };
};

class WebServer
{
public:
  WebServer(const string &listenaddress, int port, const string &password="");
  void go();

  void serveConnection(Session* client);

  typedef boost::function<string(const string& method, const string& post, const map<string,string>&varmap, bool *custom)> HandlerFunction;
  struct HandlerRegistration {
    std::list<string> urlParts;
    std::list<string> paramNames;
    HandlerFunction handler;
  };

  void registerHandler(const string& url, HandlerFunction handler);

private:
  static char B64Decode1(char cInChar);
  static int B64Decode(const std::string& strInput, std::string& strOutput);
  bool route(const std::string& url, std::map<std::string, std::string>& urlArgs, HandlerFunction** handler);

  string d_listenaddress;
  int d_port;
  std::list<HandlerRegistration> d_handlers;
  string d_password;
  Server* d_server;
};
#endif /* WEBSERVER_HH */
