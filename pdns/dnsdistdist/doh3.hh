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
#include <string>
#include <unordered_map>

#include "config.h"
#include "noinitvector.hh"

#ifdef HAVE_DNS_OVER_HTTP3
#include "channel.hh"
#include "dolog.hh"
#include "iputils.hh"
#include "libssl.hh"
#include "stat_t.hh"

struct DOH3ServerConfig;
struct DownstreamState;
#endif

namespace dnsdist::doh3
{
using h3_headers_t = std::unordered_map<std::string, std::string>;
}

#ifdef HAVE_DNS_OVER_HTTP3

#include "dnsdist-idstate.hh"
#include "doq-common.hh"

struct DOH3Frontend
{
  DOH3Frontend();
  DOH3Frontend(const DOH3Frontend&) = delete;
  DOH3Frontend(DOH3Frontend&&) = delete;
  DOH3Frontend& operator=(const DOH3Frontend&) = delete;
  DOH3Frontend& operator=(DOH3Frontend&&) = delete;
  ~DOH3Frontend();

  void setup();
  void reloadCertificates();
  const Logr::Logger& getLogger()
  {
    return *d_logger;
  }

  std::shared_ptr<const Logr::Logger> d_logger{nullptr};
  std::unique_ptr<DOH3ServerConfig> d_server_config;
  ComboAddress d_local;

#ifdef __linux__
  // On Linux this gives us 128k pending queries (default is 8192 queries),
  // which should be enough to deal with huge spikes
  uint32_t d_internalPipeBufferSize{1024 * 1024};
#else
  uint32_t d_internalPipeBufferSize{0};
#endif

  dnsdist::doq::QuicheParams d_quicheParams;
  pdns::stat_t d_doh3UnsupportedVersionErrors{0}; // Unsupported protocol version errors
  pdns::stat_t d_doh3InvalidTokensReceived{0}; // Discarded received tokens
  pdns::stat_t d_validResponses{0}; // Valid responses sent
  pdns::stat_t d_errorResponses{0}; // Empty responses (no backend, drops, invalid queries, etc.)
};

struct DOH3Unit
{
  DOH3Unit(PacketBuffer&& query_) :
    query(std::move(query_))
  {
  }

  DOH3Unit(const DOH3Unit&) = delete;
  DOH3Unit& operator=(const DOH3Unit&) = delete;

  [[nodiscard]] std::string getHTTPPath() const;
  [[nodiscard]] std::string getHTTPQueryString() const;
  [[nodiscard]] std::string getHTTPHost() const;
  [[nodiscard]] std::string getHTTPScheme() const;
  [[nodiscard]] const dnsdist::doh3::h3_headers_t& getHTTPHeaders() const;
  void setHTTPResponse(uint16_t statusCode, PacketBuffer&& body, const std::string& contentType = "");

  InternalQueryState ids;
  PacketBuffer query;
  PacketBuffer response;
  PacketBuffer serverConnID;
  dnsdist::doh3::h3_headers_t headers;
  std::shared_ptr<DownstreamState> downstream{nullptr};
  std::shared_ptr<const std::string> sni{nullptr};
  std::string d_contentTypeOut;
  DOH3ServerConfig* dsc{nullptr};
  uint64_t streamID{0};
  size_t proxyProtocolPayloadSize{0};
  uint16_t status_code{200};
  /* whether the query was re-sent to the backend over
     TCP after receiving a truncated answer over UDP */
  bool tcp{false};
};

using DOH3UnitUniquePtr = std::unique_ptr<DOH3Unit>;

struct CrossProtocolQuery;
struct DNSQuestion;
std::unique_ptr<CrossProtocolQuery> getDOH3CrossProtocolQueryFromDQ(DNSQuestion& dnsQuestion, bool isResponse);

void doh3Thread(ClientState* clientState);

#else

struct DOH3Unit
{
  [[nodiscard]] std::string getHTTPPath() const;
  [[nodiscard]] std::string getHTTPQueryString() const;
  [[nodiscard]] std::string getHTTPHost() const;
  [[nodiscard]] std::string getHTTPScheme() const;
  [[nodiscard]] const dnsdist::doh3::h3_headers_t& getHTTPHeaders() const;
  void setHTTPResponse(uint16_t, PacketBuffer&&, const std::string&);
};

struct DOH3Frontend
{
  DOH3Frontend() = default;
  void setup()
  {
  }
};

#endif
