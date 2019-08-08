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
#include "ixfrdist-web.hh"
#include <thread>
#include "threadname.hh"
#include "iputils.hh"
#include "ixfrdist-stats.hh"

string doGetStats();

IXFRDistWebServer::IXFRDistWebServer(const ComboAddress &listenAddress, const NetmaskGroup &acl, const string &loglevel) :
  d_ws(std::unique_ptr<WebServer>(new WebServer(listenAddress.toString(), listenAddress.getPort())))
{
  d_ws->setACL(acl);
  d_ws->setLogLevel(loglevel);
  d_ws->registerWebHandler("/metrics", boost::bind(&IXFRDistWebServer::getMetrics, this, _1, _2));
  d_ws->bind();
}

void IXFRDistWebServer::go() {
  setThreadName("ixfrdist/web");
  d_ws->go();
}

void IXFRDistWebServer::getMetrics(HttpRequest* req, HttpResponse* resp) {
  if(req->method != "GET")
    throw HttpMethodNotAllowedException();

  resp->body = doGetStats();
  resp->headers["Content-Type"] = "text/plain; version=0.0.4"; // https://prometheus.io/docs/instrumenting/exposition_formats/#text-based-format
  resp->status = 200;
}
