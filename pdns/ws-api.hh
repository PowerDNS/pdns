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
#include <map>
#include <optional>
#include "webserver.hh"

void apiDiscovery(HttpRequest* req, HttpResponse* resp);
void apiDiscoveryV1(HttpRequest* req, HttpResponse* resp);
void apiServer(HttpRequest* req, HttpResponse* resp);
void apiServerDetail(HttpRequest* req, HttpResponse* resp);
void apiServerConfig(HttpRequest* req, HttpResponse* resp);
void apiServerStatistics(HttpRequest* req, HttpResponse* resp);

// helpers
ZoneName apiZoneIdToName(const string& identifier);
string apiZoneNameToId(const ZoneName& name);
string apiNameToId(const std::string& name);
void apiCheckNameAllowedCharacters(std::string_view name);
void apiCheckQNameAllowedCharacters(std::string_view name);
DNSName apiNameToDNSName(const string& name);
#if defined(PDNS_AUTH)
ZoneName apiNameToZoneName(const string& name);
#endif

// To be provided by product code.
void productServerStatisticsFetch(std::map<string, string>& out);
std::optional<uint64_t> productServerStatisticsFetch(const std::string& name);
