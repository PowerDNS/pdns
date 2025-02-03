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

class NetmaskGroup;
union ComboAddress;
namespace Logr
{
class Logger;
}

namespace pdns::rust::misc
{
enum class Priority : uint8_t;
enum class LogLevel : uint8_t;
using Logger = ::Logr::Logger;
struct KeyValue;

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

uint16_t qTypeStringToCode(::rust::Str str);
bool isValidHostname(::rust::Str str);
std::unique_ptr<pdns::rust::misc::ComboAddress> comboaddress(::rust::Str str);
bool matches(const std::unique_ptr<NetmaskGroup>& nmg, const std::unique_ptr<ComboAddress>& address);
std::shared_ptr<Logger> withValue(const std::shared_ptr<Logger>& logger, ::rust::Str key, ::rust::Str val);
void log(const std::shared_ptr<Logger>& logger, Priority log_level, ::rust::Str msg, const ::rust::Vec<KeyValue>& values);
void error(const std::shared_ptr<Logger>& logger, Priority log_level, ::rust::Str err, ::rust::Str msg, const ::rust::Vec<KeyValue>& values);
}

namespace pdns::rust::web::rec
{
using CredentialsHolder = ::CredentialsHolder;
struct KeyValue;
struct Request;
struct Response;
struct IncomingWSConfig;

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
}
