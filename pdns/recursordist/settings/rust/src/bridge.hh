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

#include "rust/cxx.h"

namespace pdns::rust::settings::rec
{
uint16_t qTypeStringToCode(::rust::Str str);
bool isValidHostname(::rust::Str str);
void setThreadName(::rust::Str str);
}

namespace pdns::rust::web::rec
{
struct KeyValue;
struct Request;
struct Response;
void apiServerCacheFlush(const Request& rustRequest, Response& rustResponse);
void apiServerDetail(const Request& rustRequest, Response& rustResponse);
void apiServerStatistics(const Request& rustRequest, Response& rustResponse);
void apiServerZonesGET(const Request& rustRequest,Response& rustResponse);
void apiServerZonesPOST(const Request& rustRequest, Response& rustResponse);
void prometheusMetrics(const Request& rustRequest, Response& rustResponse);
void serveStuff(const Request& rustRequest, Response& rustResponse);
void jsonstat(const Request& rustRequest, Response& rustResponse);
}
