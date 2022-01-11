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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "logger.hh"
#include "lua-recursor4.hh"
#include "mplexer.hh"
#include "namespaces.hh"
#include "rec-lua-conf.hh"
#include "rec-protozero.hh"
#include "syncres.hh"


//! used to send information to a newborn mthread
struct DNSComboWriter {
  DNSComboWriter(const std::string& query, const struct timeval& now): d_mdp(true, query), d_now(now), d_query(query)
  {
  }

  DNSComboWriter(const std::string& query, const struct timeval& now, std::unordered_set<std::string>&& policyTags, LuaContext::LuaObject&& data, std::vector<DNSRecord>&& records): d_mdp(true, query), d_now(now), d_query(query), d_policyTags(std::move(policyTags)), d_records(std::move(records)), d_data(std::move(data))
  {
  }

  void setRemote(const ComboAddress& sa)
  {
    d_remote=sa;
  }

  void setSource(const ComboAddress& sa)
  {
    d_source=sa;
  }

  void setLocal(const ComboAddress& sa)
  {
    d_local=sa;
  }

  void setDestination(const ComboAddress& sa)
  {
    d_destination=sa;
  }

  void setSocket(int sock)
  {
    d_socket=sock;
  }

  string getRemote() const
  {
    if (d_source == d_remote) {
      return d_source.toStringWithPort();
    }
    return d_source.toStringWithPort() + " (proxied by " + d_remote.toStringWithPort() + ")";
  }

  std::vector<ProxyProtocolValue> d_proxyProtocolValues;
  MOADNSParser d_mdp;
  struct timeval d_now;
  /* Remote client, might differ from d_source
     in case of XPF, in which case d_source holds
     the IP of the client and d_remote of the proxy
  */
  ComboAddress d_remote;
  ComboAddress d_source;
  /* Destination address, might differ from
     d_destination in case of XPF, in which case
     d_destination holds the IP of the proxy and
     d_local holds our own. */
  ComboAddress d_local;
  ComboAddress d_destination;
  RecEventTrace d_eventTrace;
  boost::uuids::uuid d_uuid;
  string d_requestorId;
  string d_deviceId;
  string d_deviceName;
  struct timeval d_kernelTimestamp{0,0};
  std::string d_query;
  std::unordered_set<std::string> d_policyTags;
  std::string d_routingTag;
  std::vector<DNSRecord> d_records;
  LuaContext::LuaObject d_data;
  EDNSSubnetOpts d_ednssubnet;
  shared_ptr<TCPConnection> d_tcpConnection;
  boost::optional<uint16_t> d_extendedErrorCode{boost::none};
  string d_extendedErrorExtra;
  boost::optional<int> d_rcode{boost::none};
  int d_socket{-1};
  unsigned int d_tag{0};
  uint32_t d_qhash{0};
  uint32_t d_ttlCap{std::numeric_limits<uint32_t>::max()};
  bool d_variable{false};
  bool d_ecsFound{false};
  bool d_ecsParsed{false};
  bool d_followCNAMERecords{false};
  bool d_logResponse{false};
  bool d_tcp{false};
  bool d_responsePaddingDisabled{false};
  std::map<std::string, RecursorLua4::MetaValue> d_meta;
};


typedef MTasker<std::shared_ptr<PacketID>, PacketBuffer, PacketIDCompare> MT_t;
extern thread_local std::unique_ptr<MT_t> MT; // the big MTasker

extern thread_local FDMultiplexer* t_fdm;
extern bool g_logCommonErrors;
extern size_t g_proxyProtocolMaximumSize;
extern std::atomic<bool> g_quiet;
extern NetmaskGroup g_XPFAcl;
extern thread_local std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>> t_protobufServers;
extern thread_local std::shared_ptr<RecursorLua4> t_pdl;
extern bool g_gettagNeedsEDNSOptions;
extern NetmaskGroup g_paddingFrom;
extern unsigned int g_paddingTag;
extern thread_local std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>> t_outgoingProtobufServers;
extern unsigned int g_maxMThreads;
extern bool g_reusePort;
extern bool g_anyToTcp;
extern size_t g_tcpMaxQueriesPerConn;
extern unsigned int g_maxTCPPerClient;
extern int g_tcpTimeout;

typedef map<ComboAddress, uint32_t, ComboAddress::addressOnlyLessThan> tcpClientCounts_t;
extern thread_local std::unique_ptr<tcpClientCounts_t> t_tcpClientCounts;

typedef vector<pair<int, boost::function< void(int, boost::any&) > > > deferredAdd_t;

inline MT_t* getMT()
{
  return MT ? MT.get() : nullptr;
}

extern thread_local unsigned int t_id;

inline unsigned int getRecursorThreadId()
{
  return t_id;
}

/* this function is called with both a string and a vector<uint8_t> representing a packet */
template <class T>
static bool sendResponseOverTCP(const std::unique_ptr<DNSComboWriter>& dc, const T& packet)
{
  uint8_t buf[2];
  buf[0] = packet.size() / 256;
  buf[1] = packet.size() % 256;

  Utility::iovec iov[2];
  iov[0].iov_base = (void*)buf;              iov[0].iov_len = 2;
  iov[1].iov_base = (void*)&*packet.begin(); iov[1].iov_len = packet.size();

  int wret = Utility::writev(dc->d_socket, iov, 2);
  bool hadError = true;

  if (wret == 0) {
    g_log<<Logger::Warning<<"EOF writing TCP answer to "<<dc->getRemote()<<endl;
  } else if (wret < 0 ) {
    int err = errno;
    g_log << Logger::Warning << "Error writing TCP answer to " << dc->getRemote() << ": " << strerror(err) << endl;
  } else if ((unsigned int)wret != 2 + packet.size()) {
    g_log<<Logger::Warning<<"Oops, partial answer sent to "<<dc->getRemote()<<" for "<<dc->d_mdp.d_qname<<" (size="<< (2 + packet.size()) <<", sent "<<wret<<")"<<endl;
  } else {
    hadError = false;
  }

  return hadError;
}

PacketBuffer GenUDPQueryResponse(const ComboAddress& dest, const string& query);
bool checkProtobufExport(LocalStateHolder<LuaConfigItems>& luaconfsLocal);
bool checkFrameStreamExport(LocalStateHolder<LuaConfigItems>& luaconfsLocal);
void getQNameAndSubnet(const std::string& question, DNSName* dnsname, uint16_t* qtype, uint16_t* qclass,
                       bool& foundECS, EDNSSubnetOpts* ednssubnet, EDNSOptionViewMap* options,
                       bool& foundXPF, ComboAddress* xpfSource, ComboAddress* xpfDest);
void protobufLogQuery(LocalStateHolder<LuaConfigItems>& luaconfsLocal, const boost::uuids::uuid& uniqueId, const ComboAddress& remote, const ComboAddress& local, const Netmask& ednssubnet, bool tcp, uint16_t id, size_t len, const DNSName& qname, uint16_t qtype, uint16_t qclass, const std::unordered_set<std::string>& policyTags, const std::string& requestorId, const std::string& deviceId, const std::string& deviceName, const std::map<std::string, RecursorLua4::MetaValue>& meta);
bool isAllowNotifyForZone(DNSName qname);
bool checkForCacheHit(bool qnameParsed, unsigned int tag, const string& data,
                             DNSName& qname, uint16_t& qtype, uint16_t& qclass,
                             const struct timeval& now,
                             string& response, uint32_t& qhash,
                      RecursorPacketCache::OptPBData& pbData, bool tcp, const ComboAddress& source);
void protobufLogResponse(pdns::ProtoZero::RecMessage& message);
void protobufLogResponse(const struct dnsheader* dh, LocalStateHolder<LuaConfigItems>& luaconfsLocal,
                                const RecursorPacketCache::OptPBData& pbData, const struct timeval& tv,
                                bool tcp, const ComboAddress& source, const ComboAddress& destination,
                                const EDNSSubnetOpts& ednssubnet,
                                const boost::uuids::uuid& uniqueId, const string& requestorId, const string& deviceId,
                                const string& deviceName, const std::map<std::string, RecursorLua4::MetaValue>& meta,
                         const RecEventTrace& eventTrace);
void requestWipeCaches(const DNSName& canon);
void startDoResolve(void *p);
bool expectProxyProtocol(const ComboAddress& from);
void finishTCPReply(std::unique_ptr<DNSComboWriter>& dc, bool hadError, bool updateInFlight);
void checkFastOpenSysctl(bool active);
void checkTFOconnect();
void makeTCPServerSockets(deferredAdd_t& deferredAdds, std::set<int>& tcpSockets);
void handleNewTCPQuestion(int fd, FDMultiplexer::funcparam_t& );
