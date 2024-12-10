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

  void submit(int val);
  [[nodiscard]] double get10() const;
  [[nodiscard]] double get5() const;
  [[nodiscard]] double get1() const;
  [[nodiscard]] double getMax() const;

private:
  DTime dt;
  int d_last{};
  double d_10{}, d_5{}, d_1{}, d_max{};
};

class AuthWebServer
{
public:
  AuthWebServer();
  void go(StatBag& stats);
  static string makePercentage(const double& val);

private:
  void indexfunction(HttpRequest* req, HttpResponse* resp);
  void jsonstat(HttpRequest* req, HttpResponse* resp);
  void registerApiHandler(const string& url, std::function<void(HttpRequest*, HttpResponse*)> handler);
  void webThread();
  void statThread(StatBag& stats);

  time_t d_start;
  double d_min10{0}, d_min5{0}, d_min1{0};
  Ewma d_queries, d_cachehits, d_cachemisses;
  Ewma d_qcachehits, d_qcachemisses;
  unique_ptr<WebServer> d_ws{nullptr};
};

void apiDocs(HttpRequest* req, HttpResponse* resp);
