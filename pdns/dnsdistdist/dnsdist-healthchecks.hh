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

#include "dnsdist.hh"
#include "mplexer.hh"
#include "sstuff.hh"
#include "tcpiohandler-mplexer.hh"

extern bool g_verboseHealthChecks;

bool queueHealthCheck(std::unique_ptr<FDMultiplexer>& mplexer, const std::shared_ptr<DownstreamState>& downstream, bool initial = false);
void handleQueuedHealthChecks(FDMultiplexer& mplexer, bool initial = false);

struct HealthCheckData
{
  enum class TCPState : uint8_t
  {
    WritingQuery,
    ReadingResponseSize,
    ReadingResponse
  };

  HealthCheckData(FDMultiplexer* mplexer, std::shared_ptr<DownstreamState> downstream, DNSName&& checkName, uint16_t checkType, uint16_t checkClass, uint16_t queryID) :
    d_ds(std::move(downstream)), d_mplexer(mplexer), d_udpSocket(-1), d_checkName(std::move(checkName)), d_checkType(checkType), d_checkClass(checkClass), d_queryID(queryID)
  {
  }

  const std::shared_ptr<DownstreamState> d_ds;
  FDMultiplexer* d_mplexer{nullptr};
  std::unique_ptr<TCPIOHandler> d_tcpHandler{nullptr};
  std::unique_ptr<IOStateHandler> d_ioState{nullptr};
  PacketBuffer d_buffer;
  Socket d_udpSocket;
  DNSName d_checkName;
  struct timeval d_ttd
  {
    0, 0
  };
  size_t d_bufferPos{0};
  uint16_t d_checkType;
  uint16_t d_checkClass;
  uint16_t d_queryID;
  TCPState d_tcpState{TCPState::WritingQuery};
  bool d_initial{false};
};

PacketBuffer getHealthCheckPacket(const std::shared_ptr<DownstreamState>& ds, FDMultiplexer* mplexer, std::shared_ptr<HealthCheckData>& data);
void setHealthCheckTime(const std::shared_ptr<DownstreamState>& ds, const std::shared_ptr<HealthCheckData>& data);
bool handleResponse(std::shared_ptr<HealthCheckData>& data);
