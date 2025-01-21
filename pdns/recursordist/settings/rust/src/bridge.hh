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

#include <memory>

#include "rust/cxx.h"
#include "credentials.hh"

namespace pdns::rust::settings::rec
{
uint16_t qTypeStringToCode(::rust::Str str);
bool isValidHostname(::rust::Str str);
void setThreadName(::rust::Str str);
}

class NetmaskGroup;
union ComboAddress;

namespace pdns::rust::web::rec
{
using CredentialsHolder = ::CredentialsHolder;
// using NetmaskGroup = ::NetmaskGroup;
struct KeyValue;
struct Request;
struct Response;
struct IncomingWSConfig;

template <typename A>
class Wrapper
{
public:
  Wrapper(const A& arg);
  ~Wrapper(); // out-of-line definition, to keep A opaque

  Wrapper() = delete;
  Wrapper(const Wrapper&) = delete;
  Wrapper(Wrapper&&) = delete;
  Wrapper& operator=(const Wrapper&) = delete;
  Wrapper& operator=(Wrapper&&) = delete;

  [[nodiscard]] const A& get() const;

private:
  std::unique_ptr<A> d_ptr;
};
using NetmaskGroup = Wrapper<::NetmaskGroup>;
using ComboAddress = Wrapper<::ComboAddress>;

void apiServer(const Request& rustRequest, Response& rustResponse);
void apiDiscovery(const Request& rustRequest, Response& rustResponse);
void apiDiscoveryV1(const Request& rustRequest, Response& rustResponse);
void apiServerCacheFlush(const Request& rustRequest, Response& rustResponse);
void apiServerDetail(const Request& rustRequest, Response& rustResponse);
void apiServerStatistics(const Request& rustRequest, Response& rustResponse);
void apiServerZonesGET(const Request& rustRequest, Response& rustResponse);
void apiServerZonesPOST(const Request& rustRequest, Response& rustResponse);
void prometheusMetrics(const Request& rustRequest, Response& rustResponse);
void serveStuff(const Request& rustRequest, Response& rustResponse);
void jsonstat(const Request& rustRequest, Response& rustResponse);
void apiServerConfigAllowFromPUT(const Request& rustRequest, Response& rustResponse);
void apiServerConfigAllowFromGET(const Request& rustRequest, Response& rustResponse);
void apiServerConfigAllowNotifyFromGET(const Request& rustRequest, Response& rustResponse);
void apiServerConfigAllowNotifyFromPUT(const Request& rustRequest, Response& rustResponse);
void apiServerConfig(const Request& rustRequest, Response& rustResponse);
void apiServerRPZStats(const Request& rustRequest, Response& rustResponse);
void apiServerSearchData(const Request& rustRequest, Response& rustResponse);
void apiServerZoneDetailGET(const Request& rustRequest, Response& rustResponse);
void apiServerZoneDetailPUT(const Request& rustRequest, Response& rustResponse);
void apiServerZoneDetailDELETE(const Request& rustRequest, Response& rustResponse);
std::unique_ptr<ComboAddress> comboaddress(::rust::Str str);
bool matches(const std::unique_ptr<NetmaskGroup>& nmg, const std::unique_ptr<ComboAddress>& address);
}
