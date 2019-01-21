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
#include "config.h"

#include "dnsdist.hh"

#include "dnsdist-protobuf.hh"

#ifdef HAVE_PROTOBUF
#include "dnsmessage.pb.h"

DNSDistProtoBufMessage::DNSDistProtoBufMessage(const DNSQuestion& dq): DNSProtoBufMessage(Query, dq.uniqueId ? *dq.uniqueId : getUniqueID(), dq.remote, dq.local, *dq.qname, dq.qtype, dq.qclass, dq.dh->id, dq.tcp, dq.len)
{
  setQueryTime(dq.queryTime->tv_sec, dq.queryTime->tv_nsec / 1000);
};

DNSDistProtoBufMessage::DNSDistProtoBufMessage(const DNSResponse& dr, bool includeCNAME): DNSProtoBufMessage(Response, dr.uniqueId ? *dr.uniqueId : getUniqueID(), dr.remote, dr.local, *dr.qname, dr.qtype, dr.qclass, dr.dh->id, dr.tcp, dr.len)
{
  setQueryTime(dr.queryTime->tv_sec, dr.queryTime->tv_nsec / 1000);
  setResponseCode(dr.dh->rcode);
  addRRsFromPacket((const char*) dr.dh, dr.len, includeCNAME);
};

#endif /* HAVE_PROTOBUF */
