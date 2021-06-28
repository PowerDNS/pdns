
#include "dnsdist.hh"

DNSResponse makeDNSResponseFromIDState(IDState& ids, PacketBuffer& data, DNSQuestion::Protocol proto)
{
  DNSResponse dr(&ids.qname, ids.qtype, ids.qclass, &ids.origDest, &ids.origRemote, data, proto, &ids.sentTime.d_start);
  dr.origFlags = ids.origFlags;
  dr.ecsAdded = ids.ecsAdded;
  dr.ednsAdded = ids.ednsAdded;
  dr.useZeroScope = ids.useZeroScope;
  dr.packetCache = std::move(ids.packetCache);
  dr.delayMsec = ids.delayMsec;
  dr.skipCache = ids.skipCache;
  dr.cacheKey = ids.cacheKey;
  dr.cacheKeyNoECS = ids.cacheKeyNoECS;
  dr.dnssecOK = ids.dnssecOK;
  dr.tempFailureTTL = ids.tempFailureTTL;
  dr.qTag = std::move(ids.qTag);
  dr.subnet = std::move(ids.subnet);
  dr.uniqueId = std::move(ids.uniqueId);

  if (ids.dnsCryptQuery) {
    dr.dnsCryptQuery = std::move(ids.dnsCryptQuery);
  }

  dr.hopRemote = &ids.hopRemote;
  dr.hopLocal = &ids.hopLocal;

  return dr;
}

void setIDStateFromDNSQuestion(IDState& ids, DNSQuestion& dq, DNSName&& qname)
{
  ids.origRemote = *dq.remote;
  ids.origDest = *dq.local;
  ids.sentTime.set(*dq.queryTime);
  ids.qname = std::move(qname);
  ids.qtype = dq.qtype;
  ids.qclass = dq.qclass;
  ids.delayMsec = dq.delayMsec;
  ids.tempFailureTTL = dq.tempFailureTTL;
  ids.origFlags = dq.origFlags;
  ids.cacheKey = dq.cacheKey;
  ids.cacheKeyNoECS = dq.cacheKeyNoECS;
  ids.subnet = dq.subnet;
  ids.skipCache = dq.skipCache;
  ids.packetCache = dq.packetCache;
  ids.ednsAdded = dq.ednsAdded;
  ids.ecsAdded = dq.ecsAdded;
  ids.useZeroScope = dq.useZeroScope;
  ids.qTag = dq.qTag;
  ids.dnssecOK = dq.dnssecOK;
  ids.uniqueId = std::move(dq.uniqueId);

  if (dq.hopRemote) {
    ids.hopRemote = *dq.hopRemote;
  }
  else {
    ids.hopRemote.sin4.sin_family = 0;
  }

  if (dq.hopLocal) {
    ids.hopLocal = *dq.hopLocal;
  }
  else {
    ids.hopLocal.sin4.sin_family = 0;
  }

  ids.dnsCryptQuery = std::move(dq.dnsCryptQuery);
}
