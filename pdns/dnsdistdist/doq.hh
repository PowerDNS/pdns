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
#include "doq.hh"
#include "stat_t.hh"
#include "dnsdist-idstate.hh"

struct DOQServerConfig;
struct DownstreamState;

#ifdef HAVE_DNS_OVER_QUIC

/* from rfc9250 section-4.3 */
enum class DOQ_Error_Codes : uint64_t
{
  DOQ_NO_ERROR = 0,
  DOQ_INTERNAL_ERROR = 1,
  DOQ_PROTOCOL_ERROR = 2,
  DOQ_REQUEST_CANCELLED = 3,
  DOQ_EXCESSIVE_LOAD = 4,
  DOQ_UNSPECIFIED_ERROR = 5
};

struct DOQFrontend
{
  DOQFrontend();
  DOQFrontend(const DOQFrontend&) = delete;
  DOQFrontend(DOQFrontend&&) = delete;
  DOQFrontend& operator=(const DOQFrontend&) = delete;
  DOQFrontend& operator=(DOQFrontend&&) = delete;
  ~DOQFrontend();

  void setup();

  std::unique_ptr<DOQServerConfig> d_server_config;
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

  pdns::stat_t d_doqUnsupportedVersionErrors{0}; // Unsupported protocol version errors
  pdns::stat_t d_doqInvalidTokensReceived{0}; // Discarded received tokens
  pdns::stat_t d_validResponses{0}; // Valid responses sent
  pdns::stat_t d_errorResponses{0}; // Empty responses (no backend, drops, invalid queries, etc.)

  static std::map<const string, int> s_available_cc_algorithms;
};

struct DOQUnit
{
  DOQUnit(PacketBuffer&& query_) :
    query(std::move(query_))
  {
  }

  DOQUnit(const DOQUnit&) = delete;
  DOQUnit& operator=(const DOQUnit&) = delete;

  InternalQueryState ids;
  PacketBuffer query;
  PacketBuffer response;
  PacketBuffer serverConnID;
  std::shared_ptr<DownstreamState> downstream{nullptr};
  DOQServerConfig* dsc{nullptr};
  uint64_t streamID{0};
  size_t proxyProtocolPayloadSize{0};
  /* whether the query was re-sent to the backend over
     TCP after receiving a truncated answer over UDP */
  bool tcp{false};
};

using DOQUnitUniquePtr = std::unique_ptr<DOQUnit>;

struct CrossProtocolQuery;
struct DNSQuestion;
std::unique_ptr<CrossProtocolQuery> getDOQCrossProtocolQueryFromDQ(DNSQuestion& dnsQuestion, bool isResponse);

void doqThread(ClientState* clientState);

#else

struct DOQUnit
{
};

struct DOQFrontend
{
  DOQFrontend()
  {
  }
  void setup()
  {
  }
};

#endif
