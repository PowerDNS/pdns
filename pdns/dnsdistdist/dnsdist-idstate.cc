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
  return ids;
}
