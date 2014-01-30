/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2003 - 2011  PowerDNS.COM BV

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
#include <boost/utility.hpp> 
#include "namespaces.hh"
#include "mplexer.hh"
#include "webserver.hh"

class RecursorWebServer : public boost::noncopyable
{
public:
  explicit RecursorWebServer(FDMultiplexer* fdm);
  void jsonstat(HttpRequest* req, HttpResponse *resp);

private:
  AsyncWebServer* d_ws;
};

string returnJSONStats(const map<string, string>& items);
