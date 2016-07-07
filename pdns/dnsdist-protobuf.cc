
#include "config.h"

#include "dnsdist.hh"
#include "gettime.hh"

#include "dnsparser.hh"
#include "dnsdist-protobuf.hh"

#ifdef HAVE_PROTOBUF
#include "dnsmessage.pb.h"

DNSDistProtoBufMessage::DNSDistProtoBufMessage(DNSProtoBufMessageType type, const DNSQuestion& dq): DNSProtoBufMessage(type, dq.uniqueId, dq.remote, dq.local, *dq.qname, dq.qtype, dq.qclass, dq.dh->id, dq.tcp, dq.len)
{
  if (type == Response) {
    PBDNSMessage_DNSResponse* response = d_message.mutable_response();
    if (response) {
      response->set_rcode(dq.dh->rcode);
    }
    addRRsFromPacket((const char*) dq.dh, dq.len);
  }
};

DNSDistProtoBufMessage::DNSDistProtoBufMessage(const DNSResponse& dr): DNSProtoBufMessage(Response, dr.uniqueId, dr.remote, dr.local, *dr.qname, dr.qtype, dr.qclass, dr.dh->id, dr.tcp, dr.len)
{
  setQueryTime(dr.queryTime->tv_sec, dr.queryTime->tv_nsec / 1000);
  setResponseCode(dr.dh->rcode);
  addRRsFromPacket((const char*) dr.dh, dr.len);
};

#endif /* HAVE_PROTOBUF */
