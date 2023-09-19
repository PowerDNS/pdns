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
#include "channel.hh"
#include "iputils.hh"
#include "libssl.hh"
#include "noinitvector.hh"
#include "stat_t.hh"
#include "dnsdist-idstate.hh"

#ifdef HAVE_DNS_OVER_QUIC

#include <quiche.h>

using QuicheConnection = std::unique_ptr<quiche_conn, decltype(&quiche_conn_free)>;
using QuicheConfig = std::unique_ptr<quiche_config, decltype(&quiche_config_free)>;

class Connection
{
public:
  Connection(const ComboAddress& peer, std::unique_ptr<quiche_conn, decltype(&quiche_conn_free)>&& conn) :
    d_peer(peer), d_conn(std::move(conn))
  {
  }
  Connection(const Connection&) = delete;
  Connection(Connection&&) = default;
  Connection& operator=(const Connection&) = delete;
  Connection& operator=(Connection&&) = default;
  ~Connection() = default;

  ComboAddress d_peer;
  QuicheConnection d_conn;
};

#endif

struct DOQServerConfig;
struct DownstreamState;

#ifdef HAVE_DNS_OVER_QUIC

struct DOQFrontend
{
  DOQFrontend()
  {
  }

  std::shared_ptr<DOQServerConfig> d_server_config{nullptr};
  TLSConfig d_tlsConfig;
  ComboAddress d_local;

  void setup();
};

struct DOQUnit
{
  DOQUnit(PacketBuffer&& q) :
    query(std::move(q))
  {
    ids.ednsAdded = false;
  }

  DOQUnit(const DOQUnit&) = delete;
  DOQUnit& operator=(const DOQUnit&) = delete;

  InternalQueryState ids;
  PacketBuffer query;
  PacketBuffer response;
  std::shared_ptr<DownstreamState> downstream{nullptr};
  DOQServerConfig* dsc{nullptr};
  pdns::channel::Sender<DOQUnit>* responseSender{nullptr};
  size_t proxyProtocolPayloadSize{0};
  uint64_t streamID{0};
  PacketBuffer serverConnID;
  /* whether the query was re-sent to the backend over
     TCP after receiving a truncated answer over UDP */
  bool tcp{false};
  bool truncated{false};
};

using DOQUnitUniquePtr = std::unique_ptr<DOQUnit>;

struct CrossProtocolQuery;
struct DNSQuestion;
std::unique_ptr<CrossProtocolQuery> getDOQCrossProtocolQueryFromDQ(DNSQuestion& dq, bool isResponse);

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
