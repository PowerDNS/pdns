/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2014  PowerDNS.COM BV

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
#ifndef PDNS_WSAPI_HH
#define PDNS_WSAPI_HH

#include <map>
#include "webserver.hh"

void apiDiscovery(HttpRequest* req, HttpResponse* resp);
void apiServer(HttpRequest* req, HttpResponse* resp);
void apiServerDetail(HttpRequest* req, HttpResponse* resp);
void apiServerConfig(HttpRequest* req, HttpResponse* resp);
void apiServerSearchLog(HttpRequest* req, HttpResponse* resp);
void apiServerStatistics(HttpRequest* req, HttpResponse* resp);

// helpers
DNSName apiZoneIdToName(const string& id);
string apiZoneNameToId(const DNSName& name);
void apiCheckNameAllowedCharacters(const string& name);
void apiCheckQNameAllowedCharacters(const string& name);
DNSName apiNameToDNSName(const string& name);

// To be provided by product code.
void productServerStatisticsFetch(std::map<string,string>& out);

#endif /* PDNS_WSAPI_HH */
