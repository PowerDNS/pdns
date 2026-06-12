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
#include <string>
#include <map>
#include <ctime>
#include <pthread.h>
#include "misc.hh"
#include "namespaces.hh"
#include "webserver.hh"
#include "statbag.hh"

class Ewma
{
public:
  Ewma();

  void submit(unsigned long val);
  [[nodiscard]] double get10() const;
  [[nodiscard]] double get5() const;
  [[nodiscard]] double get1() const;
  [[nodiscard]] double getMax() const;

private:
  DTime dt;
  unsigned long d_last{};
  double d_10{}, d_5{}, d_1{}, d_max{};
};

class ApiWebServer : public WebServer
{
public:
  ApiWebServer(std::shared_ptr<ConcurrentConnectionManager> ccm, string listenaddress, int port);
  virtual ~ApiWebServer() = default;

  void registerApiHandler(const string& url, const HandlerFunction& handler, const std::string& method, bool allowPassword) override;

protected:
  AtomicCounter* d_api_queries{nullptr};
  AtomicCounter* d_api_result_200{nullptr};
  AtomicCounter* d_api_result_201{nullptr};
  AtomicCounter* d_api_result_204{nullptr};
  AtomicCounter* d_api_result_409{nullptr};
  AtomicCounter* d_api_result_422{nullptr};
  AtomicCounter* d_api_result_500{nullptr};
};

class AuthWebServer
{
public:
  AuthWebServer();
  void go(Logr::log_t slog);
  static string makePercentage(const double& val);

private:
  void indexGET(HttpRequest* req, HttpResponse* resp);
  void indexPOST(HttpRequest* req, HttpResponse* resp);
  void registerApiHandler(const string& url, std::function<void(HttpRequest*, HttpResponse*)> handler);
  void webThread(Logr::log_t slog);
  void statThread(Logr::log_t slog);

  time_t d_start;
  double d_min10{0}, d_min5{0}, d_min1{0};
  Ewma d_queries, d_cachehits, d_cachemisses;
  Ewma d_qcachehits, d_qcachemisses;
  Ewma d_api_queries;
  unique_ptr<WebServer> d_ws{nullptr};
  std::string d_unique;

  bool d_doApi{false};
};

void apiDocs(HttpRequest* req, HttpResponse* resp);
