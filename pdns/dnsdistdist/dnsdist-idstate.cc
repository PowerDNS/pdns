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

#include "dnsdist-idstate.hh"
#include "dnsdist-doh-common.hh"
#include "doh3.hh"
#include "doq.hh"

InternalQueryState InternalQueryState::partialCloneForXFR() const
{
  /* for XFR responses we cannot move the state from the query
     because we usually have more than one response packet per query,
     so we need to do a partial clone.
  */
  InternalQueryState ids;
  ids.qtype = qtype;
  ids.qclass = qclass;
  ids.qname = qname;
  ids.poolName = poolName;
  ids.queryRealTime = queryRealTime;
  ids.protocol = protocol;
  ids.subnet = subnet;
  ids.origRemote = origRemote;
  ids.origDest = origDest;
  ids.hopRemote = hopRemote;
  ids.hopLocal = hopLocal;
  if (qTag) {
    ids.qTag = std::make_unique<QTag>(*qTag);
  }
  if (d_protoBufData) {
    ids.d_protoBufData = std::make_unique<InternalQueryState::ProtoBufData>(*d_protoBufData);
  }
  ids.cs = cs;
  /* in case we want to support XFR over DoH, or the stream ID becomes used for QUIC */
  ids.d_streamID = d_streamID;
#if !defined(DISABLE_PROTOBUF)
  ids.d_rawProtobufContent = d_rawProtobufContent;
#endif
  return ids;
}

void InternalQueryState::sendDelayedProtobufMessages() const
{
#ifndef DISABLE_PROTOBUF
  static thread_local string otPBBuf;
  otPBBuf.clear();
  if (tracingEnabled) {
    pdns::ProtoZero::Message msg{otPBBuf};
    msg.setOpenTelemetryData(d_OTTracer->getOTProtobuf());
  }

  for (auto const& msg_logger : delayedResponseMsgs) {
    // TODO: we should probably do something with the return value of queueData
    if (!tracingEnabled) {
      msg_logger.second->queueData(msg_logger.first);
      continue;
    }
    // Protobuf wireformat allows us to simply append the second "message"
    // that only contains the OTTrace data as a single bytes field
    msg_logger.second->queueData(msg_logger.first + otPBBuf);
  }
#endif
}

std::optional<pdns::trace::dnsdist::Tracer::Closer> InternalQueryState::getCloser([[maybe_unused]] const std::string& name, [[maybe_unused]] const SpanID& parentSpanID)
{
  std::optional<pdns::trace::dnsdist::Tracer::Closer> ret(std::nullopt);
#ifndef DISABLE_PROTOBUF
  // getTracer returns a Tracer when tracing is globally enabled
  // tracingEnabled tells us whether or not tracing is enabled for this query
  // Should tracing be disabled, *but* we have not processed query rules, we will still return a closer if tracing is globally enabled
  if (auto tracer = getTracer(); tracer != nullptr && (tracingEnabled || !tracingPastProcessRules)) {
    ret = std::optional<pdns::trace::dnsdist::Tracer::Closer>(d_OTTracer->openSpan(name, parentSpanID));
  }
#endif
  return ret;
}

std::optional<pdns::trace::dnsdist::Tracer::Closer> InternalQueryState::getCloser([[maybe_unused]] const std::string& name, [[maybe_unused]] const std::string& parentSpanName)
{
  std::optional<pdns::trace::dnsdist::Tracer::Closer> ret(std::nullopt);
#ifndef DISABLE_PROTOBUF
  if (auto tracer = getTracer(); tracer != nullptr) {
    auto parentSpanID = d_OTTracer->getLastSpanIDForName(parentSpanName);
    return getCloser(name, parentSpanID);
  }
#endif
  return ret;
}

std::optional<pdns::trace::dnsdist::Tracer::Closer> InternalQueryState::getCloser([[maybe_unused]] const std::string& name)
{
  std::optional<pdns::trace::dnsdist::Tracer::Closer> ret(std::nullopt);
#ifndef DISABLE_PROTOBUF
  if (auto tracer = getTracer(); tracer != nullptr) {
    return getCloser(name, d_OTTracer->getLastSpanID());
  }
#endif
  return ret;
}
