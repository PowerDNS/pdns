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

#include "webserver.hh"

class HttpRequest;
class HttpResponse;
extern void serveRustWeb();

#ifndef RUST_WS

#include <boost/utility.hpp>
#include "namespaces.hh"
#include "mplexer.hh"

class AsyncServer : public Server
{
public:
  AsyncServer(const string& localaddress, int port) :
    Server(localaddress, port)
  {
    d_server_socket.setNonBlocking();
  };

  friend void AsyncServerNewConnectionMT(void* arg);

  using newconnectioncb_t = std::function<void(const std::shared_ptr<Socket>&)>;
  void asyncWaitForConnections(FDMultiplexer* fdm, const newconnectioncb_t& callback);

private:
  void newConnection();

  newconnectioncb_t d_asyncNewConnectionCallback;
};

class AsyncWebServer : public WebServer
{
public:
  AsyncWebServer(FDMultiplexer* fdm, const string& listenaddress, int port) :
    WebServer(listenaddress, port), d_fdm(fdm){};
  void go();

private:
  FDMultiplexer* d_fdm;
  void serveConnection(const std::shared_ptr<Socket>& socket) const;

protected:
  std::shared_ptr<Server> createServer() override
  {
    return std::make_shared<AsyncServer>(d_listenaddress, d_port);
  };
};

class RecursorWebServer : public boost::noncopyable
{
public:
  explicit RecursorWebServer(FDMultiplexer* fdm);
  static void jsonstat(HttpRequest* req, HttpResponse* resp);

private:
  std::unique_ptr<AsyncWebServer> d_ws{nullptr};
};
#endif
