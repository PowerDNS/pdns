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

#include "config.h"
#include "channel.hh"
#include "iputils.hh"
#include "libssl.hh"
#include "noinitvector.hh"
#include "stat_t.hh"
#include "dnsdist-idstate.hh"

struct DOH3ServerConfig;
struct DownstreamState;

#ifdef HAVE_DNS_OVER_HTTP3

struct DOH3Frontend
{
  DOH3Frontend();
  DOH3Frontend(const DOH3Frontend&) = delete;
  DOH3Frontend(DOH3Frontend&&) = delete;
  DOH3Frontend& operator=(const DOH3Frontend&) = delete;
  DOH3Frontend& operator=(DOH3Frontend&&) = delete;
  ~DOH3Frontend();

  void setup();

  std::unique_ptr<DOH3ServerConfig> d_server_config;
  TLSConfig d_tlsConfig;
  ComboAddress d_local;
  std::string d_keyLogFile;

#ifdef __linux__
  // On Linux this gives us 128k pending queries (default is 8192 queries),
  // which should be enough to deal with huge spikes
  uint32_t d_internalPipeBufferSize{1024 * 1024};
#else
  uint32_t d_internalPipeBufferSize{0};
#endif
  uint64_t d_idleTimeout{5};
  uint64_t d_maxInFlight{65535};
  std::string d_ccAlgo{"reno"};

  pdns::stat_t d_doh3UnsupportedVersionErrors{0}; // Unsupported protocol version errors
  pdns::stat_t d_doh3InvalidTokensReceived{0}; // Discarded received tokens
  pdns::stat_t d_validResponses{0}; // Valid responses sent
  pdns::stat_t d_errorResponses{0}; // Empty responses (no backend, drops, invalid queries, etc.)

  static std::map<const string, int> s_available_cc_algorithms;
};

struct DOH3Unit
{
  DOH3Unit(PacketBuffer&& query_) :
    query(std::move(query_))
  {
  }

  DOH3Unit(const DOH3Unit&) = delete;
  DOH3Unit& operator=(const DOH3Unit&) = delete;

  InternalQueryState ids;
  PacketBuffer query;
  PacketBuffer response;
  PacketBuffer serverConnID;
  std::shared_ptr<DownstreamState> downstream{nullptr};
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
};

struct DOH3Frontend
{
  DOH3Frontend()
  {
  }
  void setup()
  {
  }
};

#endif
