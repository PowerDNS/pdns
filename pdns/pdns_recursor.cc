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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdb.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef HAVE_BOOST_CONTAINER_FLAT_SET_HPP
#include <boost/container/flat_set.hpp>
#endif
#include "ws-recursor.hh"
#include <thread>
#include "threadname.hh"
#include "recpacketcache.hh"
#include "utility.hh"
#include "dns_random.hh"
#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#endif
#include "opensslsigners.hh"
#include <iostream>
#include <errno.h>
#include <boost/static_assert.hpp>
#include <map>
#include <set>
#include "recursor_cache.hh"
#include "cachecleaner.hh"
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include "misc.hh"
#include "mtasker.hh"
#include <utility>
#include "arguments.hh"
#include "syncres.hh"
#include <fcntl.h>
#include <fstream>
#include "sortlist.hh"
#include "sstuff.hh"
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/shared_array.hpp>
#include <boost/function.hpp>
#include <boost/algorithm/string.hpp>
#ifdef MALLOC_TRACE
#include "malloctrace.hh"
#endif
#include <netinet/tcp.h>
#include "capabilities.hh"
#include "dnsparser.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "zoneparser-tng.hh"
#include "rec_channel.hh"
#include "logger.hh"
#include "iputils.hh"
#include "mplexer.hh"
#include "config.h"
#include "lua-recursor4.hh"
#include "version.hh"
#include "responsestats.hh"
#include "secpoll-recursor.hh"
#include "dnsname.hh"
#include "filterpo.hh"
#include "rpzloader.hh"
#include "validate-recursor.hh"
#include "rec-lua-conf.hh"
#include "ednsoptions.hh"
#include "gettime.hh"
#include "pubsuffix.hh"
#ifdef NOD_ENABLED
#include "nod.hh"
#endif /* NOD_ENABLED */

#include "rec-protobuf.hh"
#include "rec-snmp.hh"

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "namespaces.hh"

#ifdef HAVE_PROTOBUF
#include "uuid-utils.hh"
#endif /* HAVE_PROTOBUF */

#include "xpf.hh"

typedef map<ComboAddress, uint32_t, ComboAddress::addressOnlyLessThan> tcpClientCounts_t;

static thread_local std::shared_ptr<RecursorLua4> t_pdl;
static thread_local unsigned int t_id = 0;
static thread_local std::shared_ptr<Regex> t_traceRegex;
static thread_local std::unique_ptr<tcpClientCounts_t> t_tcpClientCounts;
#ifdef HAVE_PROTOBUF
static thread_local std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>> t_protobufServers{nullptr};
static thread_local uint64_t t_protobufServersGeneration;
static thread_local std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>> t_outgoingProtobufServers{nullptr};
static thread_local uint64_t t_outgoingProtobufServersGeneration;
#endif /* HAVE_PROTOBUF */

#ifdef HAVE_FSTRM
static thread_local std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>> t_frameStreamServers{nullptr};
static thread_local uint64_t t_frameStreamServersGeneration;
#endif /* HAVE_FSTRM */

thread_local std::unique_ptr<MT_t> MT; // the big MTasker
thread_local std::unique_ptr<MemRecursorCache> t_RC;
thread_local std::unique_ptr<RecursorPacketCache> t_packetCache;
thread_local FDMultiplexer* t_fdm{nullptr};
thread_local std::unique_ptr<addrringbuf_t> t_remotes, t_servfailremotes, t_largeanswerremotes, t_bogusremotes;
thread_local std::unique_ptr<boost::circular_buffer<pair<DNSName, uint16_t> > > t_queryring, t_servfailqueryring, t_bogusqueryring;
thread_local std::shared_ptr<NetmaskGroup> t_allowFrom;
#ifdef NOD_ENABLED
thread_local std::shared_ptr<nod::NODDB> t_nodDBp;
thread_local std::shared_ptr<nod::UniqueResponseDB> t_udrDBp;
#endif /* NOD_ENABLED */
__thread struct timeval g_now; // timestamp, updated (too) frequently

typedef vector<pair<int, function< void(int, any&) > > > deferredAdd_t;

// for communicating with our threads
// effectively readonly after startup
struct RecThreadInfo
{
  struct ThreadPipeSet
  {
    int writeToThread{-1};
    int readToThread{-1};
    int writeFromThread{-1};
    int readFromThread{-1};
    int writeQueriesToThread{-1}; // this one is non-blocking
    int readQueriesToThread{-1};
  };

  /* FD corresponding to TCP sockets this thread is listening
     on.
     These FDs are also in deferredAdds when we have one
     socket per listener, and in g_deferredAdds instead. */
  std::set<int> tcpSockets;
  /* FD corresponding to listening sockets if we have one socket per
     listener (with reuseport), otherwise all listeners share the
     same FD and g_deferredAdds is then used instead */
  deferredAdd_t deferredAdds;
  struct ThreadPipeSet pipes;
  std::thread thread;
  MT_t* mt{nullptr};
  uint64_t numberOfDistributedQueries{0};
  /* handle the web server, carbon, statistics and the control channel */
  bool isHandler{false};
  /* accept incoming queries (and distributes them to the workers if pdns-distributes-queries is set) */
  bool isListener{false};
  /* process queries */
  bool isWorker{false};
};

/* first we have the handler thread, t_id == 0 (some other
   helper threads like SNMP might have t_id == 0 as well)
   then the distributor threads if any
   and finally the workers */
static std::vector<RecThreadInfo> s_threadInfos;
/* without reuseport, all listeners share the same sockets */
static deferredAdd_t g_deferredAdds;

typedef vector<int> tcpListenSockets_t;
typedef map<int, ComboAddress> listenSocketsAddresses_t; // is shared across all threads right now

static const ComboAddress g_local4("0.0.0.0"), g_local6("::");
static listenSocketsAddresses_t g_listenSocketsAddresses; // is shared across all threads right now
static set<int> g_fromtosockets; // listen sockets that use 'sendfromto()' mechanism
static vector<ComboAddress> g_localQueryAddresses4, g_localQueryAddresses6;
static AtomicCounter counter;
static std::shared_ptr<SyncRes::domainmap_t> g_initialDomainMap; // new threads needs this to be setup
static std::shared_ptr<NetmaskGroup> g_initialAllowFrom; // new thread needs to be setup with this
static NetmaskGroup g_XPFAcl;
static size_t g_tcpMaxQueriesPerConn;
static size_t s_maxUDPQueriesPerRound;
static uint64_t g_latencyStatSize;
static uint32_t g_disthashseed;
static unsigned int g_maxTCPPerClient;
static unsigned int g_maxMThreads;
static unsigned int g_numDistributorThreads;
static unsigned int g_numWorkerThreads;
static int g_tcpTimeout;
static uint16_t g_udpTruncationThreshold;
static uint16_t g_xpfRRCode{0};
static std::atomic<bool> statsWanted;
static std::atomic<bool> g_quiet;
static bool g_logCommonErrors;
static bool g_anyToTcp;
static bool g_weDistributeQueries; // if true, 1 or more threads listen on the incoming query sockets and distribute them to workers
static bool g_reusePort{false};
static bool g_gettagNeedsEDNSOptions{false};
static time_t g_statisticsInterval;
static bool g_useIncomingECS;
static bool g_useKernelTimestamp;
std::atomic<uint32_t> g_maxCacheEntries, g_maxPacketCacheEntries;
#ifdef NOD_ENABLED
static bool g_nodEnabled;
static DNSName g_nodLookupDomain;
static bool g_nodLog;
static SuffixMatchNode g_nodDomainWL;
static std::string g_nod_pbtag;
static bool g_udrEnabled;
static bool g_udrLog;
static std::string g_udr_pbtag;
#endif /* NOD_ENABLED */
#ifdef HAVE_BOOST_CONTAINER_FLAT_SET_HPP
static boost::container::flat_set<uint16_t> s_avoidUdpSourcePorts;
#else
static std::set<uint16_t> s_avoidUdpSourcePorts;
#endif
static uint16_t s_minUdpSourcePort;
static uint16_t s_maxUdpSourcePort;
static double s_balancingFactor;

RecursorControlChannel s_rcc; // only active in the handler thread
RecursorStats g_stats;
string s_programname="pdns_recursor";
string s_pidfname;
bool g_lowercaseOutgoing;
unsigned int g_networkTimeoutMsec;
unsigned int g_numThreads;
uint16_t g_outgoingEDNSBufsize;
bool g_logRPZChanges{false};

// Used in the Syncres to not throttle certain servers
GlobalStateHolder<SuffixMatchNode> g_dontThrottleNames;
GlobalStateHolder<NetmaskGroup> g_dontThrottleNetmasks;

#define LOCAL_NETS "127.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 192.168.0.0/16, 172.16.0.0/12, ::1/128, fc00::/7, fe80::/10"
#define LOCAL_NETS_INVERSE "!127.0.0.0/8, !10.0.0.0/8, !100.64.0.0/10, !169.254.0.0/16, !192.168.0.0/16, !172.16.0.0/12, !::1/128, !fc00::/7, !fe80::/10"
// Bad Nets taken from both:
// http://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
// and
// http://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
// where such a network may not be considered a valid destination
#define BAD_NETS   "0.0.0.0/8, 192.0.0.0/24, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 240.0.0.0/4, ::/96, ::ffff:0:0/96, 100::/64, 2001:db8::/32"
#define DONT_QUERY LOCAL_NETS ", " BAD_NETS

//! used to send information to a newborn mthread
struct DNSComboWriter {
  DNSComboWriter(const std::string& query, const struct timeval& now): d_mdp(true, query), d_now(now), d_query(query)
  {
  }

  DNSComboWriter(const std::string& query, const struct timeval& now, std::vector<std::string>&& policyTags, LuaContext::LuaObject&& data, std::vector<DNSRecord>&& records): d_mdp(true, query), d_now(now), d_query(query), d_policyTags(std::move(policyTags)), d_records(std::move(records)), d_data(std::move(data))
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
#ifdef HAVE_PROTOBUF
  boost::uuids::uuid d_uuid;
  string d_requestorId;
  string d_deviceId;
  string d_deviceName;
  struct timeval d_kernelTimestamp{0,0};
#endif
  std::string d_query;
  std::vector<std::string> d_policyTags;
  std::vector<DNSRecord> d_records;
  LuaContext::LuaObject d_data;
  EDNSSubnetOpts d_ednssubnet;
  shared_ptr<TCPConnection> d_tcpConnection;
  boost::optional<int> d_rcode{boost::none};
  int d_socket{-1};
  unsigned int d_tag{0};
  uint32_t d_qhash{0};
  uint32_t d_ttlCap{std::numeric_limits<uint32_t>::max()};
  uint16_t d_ecsBegin{0};
  uint16_t d_ecsEnd{0};
  bool d_variable{false};
  bool d_ecsFound{false};
  bool d_ecsParsed{false};
  bool d_followCNAMERecords{false};
  bool d_logResponse{false};
  bool d_tcp{false};
};

MT_t* getMT()
{
  return MT ? MT.get() : nullptr;
}

ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}

unsigned int getRecursorThreadId()
{
  return t_id;
}

int getMTaskerTID()
{
  return MT->getTid();
}

static bool isDistributorThread()
{
  if (t_id == 0) {
    return false;
  }

  return g_weDistributeQueries && s_threadInfos.at(t_id).isListener;
}

static bool isHandlerThread()
{
  if (t_id == 0) {
    return true;
  }

  return s_threadInfos.at(t_id).isHandler;
}

static void handleTCPClientWritable(int fd, FDMultiplexer::funcparam_t& var);

// -1 is error, 0 is timeout, 1 is success
int asendtcp(const string& data, Socket* sock)
{
  PacketID pident;
  pident.sock=sock;
  pident.outMSG=data;

  t_fdm->addWriteFD(sock->getHandle(), handleTCPClientWritable, pident);
  string packet;

  int ret=MT->waitEvent(pident, &packet, g_networkTimeoutMsec);

  if(!ret || ret==-1) { // timeout
    t_fdm->removeWriteFD(sock->getHandle());
  }
  else if(packet.size() !=data.size()) { // main loop tells us what it sent out, or empty in case of an error
    return -1;
  }
  return ret;
}

static void handleTCPClientReadable(int fd, FDMultiplexer::funcparam_t& var);

// -1 is error, 0 is timeout, 1 is success
int arecvtcp(string& data, size_t len, Socket* sock, bool incompleteOkay)
{
  data.clear();
  PacketID pident;
  pident.sock=sock;
  pident.inNeeded=len;
  pident.inIncompleteOkay=incompleteOkay;
  t_fdm->addReadFD(sock->getHandle(), handleTCPClientReadable, pident);

  int ret=MT->waitEvent(pident,&data, g_networkTimeoutMsec);
  if(!ret || ret==-1) { // timeout
    t_fdm->removeReadFD(sock->getHandle());
  }
  else if(data.empty()) {// error, EOF or other
    return -1;
  }

  return ret;
}

static void handleGenUDPQueryResponse(int fd, FDMultiplexer::funcparam_t& var)
{
  PacketID pident=*any_cast<PacketID>(&var);
  char resp[512];
  ComboAddress fromaddr;
  socklen_t addrlen=sizeof(fromaddr);

  ssize_t ret=recvfrom(fd, resp, sizeof(resp), 0, (sockaddr *)&fromaddr, &addrlen);
  if (fromaddr != pident.remote) {
    g_log<<Logger::Notice<<"Response received from the wrong remote host ("<<fromaddr.toStringWithPort()<<" instead of "<<pident.remote.toStringWithPort()<<"), discarding"<<endl;

  }

  t_fdm->removeReadFD(fd);
  if(ret >= 0) {
    string data(resp, (size_t) ret);
    MT->sendEvent(pident, &data);
  }
  else {
    string empty;
    MT->sendEvent(pident, &empty);
    //    cerr<<"Had some kind of error: "<<ret<<", "<<stringerror()<<endl;
  }
}
string GenUDPQueryResponse(const ComboAddress& dest, const string& query)
{
  Socket s(dest.sin4.sin_family, SOCK_DGRAM);
  s.setNonBlocking();
  ComboAddress local = getQueryLocalAddress(dest.sin4.sin_family, 0);
  
  s.bind(local);
  s.connect(dest);
  s.send(query);

  PacketID pident;
  pident.sock=&s;
  pident.remote=dest;
  pident.type=0;
  t_fdm->addReadFD(s.getHandle(), handleGenUDPQueryResponse, pident);

  string data;
 
  int ret=MT->waitEvent(pident,&data, g_networkTimeoutMsec);
 
  if(!ret || ret==-1) { // timeout
    t_fdm->removeReadFD(s.getHandle());
  }
  else if(data.empty()) {// error, EOF or other
    // we could special case this
    return data;
  }
  return data;
}

//! pick a random query local address
ComboAddress getQueryLocalAddress(int family, uint16_t port)
{
  ComboAddress ret;
  if(family==AF_INET) {
    if(g_localQueryAddresses4.empty())
      ret = g_local4;
    else
      ret = g_localQueryAddresses4[dns_random(g_localQueryAddresses4.size())];
    ret.sin4.sin_port = htons(port);
  }
  else {
    if(g_localQueryAddresses6.empty())
      ret = g_local6;
    else
      ret = g_localQueryAddresses6[dns_random(g_localQueryAddresses6.size())];

    ret.sin6.sin6_port = htons(port);
  }
  return ret;
}

static void handleUDPServerResponse(int fd, FDMultiplexer::funcparam_t&);

static void setSocketBuffer(int fd, int optname, uint32_t size)
{
  uint32_t psize=0;
  socklen_t len=sizeof(psize);

  if(!getsockopt(fd, SOL_SOCKET, optname, (char*)&psize, &len) && psize > size) {
    g_log<<Logger::Error<<"Not decreasing socket buffer size from "<<psize<<" to "<<size<<endl;
    return;
  }

  if (setsockopt(fd, SOL_SOCKET, optname, (char*)&size, sizeof(size)) < 0) {
    int err = errno;
    g_log << Logger::Error << "Unable to raise socket buffer size to " << size << ": " << stringerror(err) << endl;
  }
}


static void setSocketReceiveBuffer(int fd, uint32_t size)
{
  setSocketBuffer(fd, SO_RCVBUF, size);
}

static void setSocketSendBuffer(int fd, uint32_t size)
{
  setSocketBuffer(fd, SO_SNDBUF, size);
}


// you can ask this class for a UDP socket to send a query from
// this socket is not yours, don't even think about deleting it
// but after you call 'returnSocket' on it, don't assume anything anymore
class UDPClientSocks
{
  unsigned int d_numsocks;
public:
  UDPClientSocks() : d_numsocks(0)
  {
  }

  // returning -2 means: temporary OS error (ie, out of files), -1 means error related to remote
  int getSocket(const ComboAddress& toaddr, int* fd)
  {
    *fd=makeClientSocket(toaddr.sin4.sin_family);
    if(*fd < 0) // temporary error - receive exception otherwise
      return -2;

    if(connect(*fd, (struct sockaddr*)(&toaddr), toaddr.getSocklen()) < 0) {
      int err = errno;
      try {
        closesocket(*fd);
      }
      catch(const PDNSException& e) {
        g_log<<Logger::Error<<"Error closing UDP socket after connect() failed: "<<e.reason<<endl;
      }

      if(err==ENETUNREACH) // Seth "My Interfaces Are Like A Yo Yo" Arnold special
        return -2;
      return -1;
    }

    d_numsocks++;
    return 0;
  }

  // return a socket to the pool, or simply erase it
  void returnSocket(int fd)
  {
    try {
      t_fdm->removeReadFD(fd);
    }
    catch(const FDMultiplexerException& e) {
      // we sometimes return a socket that has not yet been assigned to t_fdm
    }

    try {
      closesocket(fd);
    }
    catch(const PDNSException& e) {
      g_log<<Logger::Error<<"Error closing returned UDP socket: "<<e.reason<<endl;
    }

    --d_numsocks;
  }

private:

  // returns -1 for errors which might go away, throws for ones that won't
  static int makeClientSocket(int family)
  {
    int ret=socket(family, SOCK_DGRAM, 0 ); // turns out that setting CLO_EXEC and NONBLOCK from here is not a performance win on Linux (oddly enough)

    if(ret < 0 && errno==EMFILE) // this is not a catastrophic error
      return ret;

    if(ret<0)
      throw PDNSException("Making a socket for resolver (family = "+std::to_string(family)+"): "+stringerror());

    //    setCloseOnExec(ret); // we're not going to exec

    int tries=10;
    ComboAddress sin;
    while(--tries) {
      uint16_t port;

      if(tries==1)  // fall back to kernel 'random'
        port = 0;
      else {
        do {
          port = s_minUdpSourcePort + dns_random(s_maxUdpSourcePort - s_minUdpSourcePort + 1);
        }
        while (s_avoidUdpSourcePorts.count(port));
      }

      sin=getQueryLocalAddress(family, port); // does htons for us

      if (::bind(ret, (struct sockaddr *)&sin, sin.getSocklen()) >= 0)
        break;
    }

    if(!tries) {
      closesocket(ret);
      throw PDNSException("Resolver binding to local query client socket on "+sin.toString()+": "+stringerror());
    }

    try {
      setReceiveSocketErrors(ret, family);
      setNonBlocking(ret);
    }
    catch(...) {
      closesocket(ret);
      throw;
    }

    return ret;
  }
};

static thread_local std::unique_ptr<UDPClientSocks> t_udpclientsocks;

/* these two functions are used by LWRes */
// -2 is OS error, -1 is error that depends on the remote, > 0 is success
int asendto(const char *data, size_t len, int flags,
            const ComboAddress& toaddr, uint16_t id, const DNSName& domain, uint16_t qtype, int* fd)
{

  PacketID pident;
  pident.domain = domain;
  pident.remote = toaddr;
  pident.type = qtype;

  // see if there is an existing outstanding request we can chain on to, using partial equivalence function
  pair<MT_t::waiters_t::iterator, MT_t::waiters_t::iterator> chain=MT->d_waiters.equal_range(pident, PacketIDBirthdayCompare());

  for(; chain.first != chain.second; chain.first++) {
    if(chain.first->key.fd > -1) { // don't chain onto existing chained waiter!
      /*
      cerr<<"Orig: "<<pident.domain<<", "<<pident.remote.toString()<<", id="<<id<<endl;
      cerr<<"Had hit: "<< chain.first->key.domain<<", "<<chain.first->key.remote.toString()<<", id="<<chain.first->key.id
          <<", count="<<chain.first->key.chain.size()<<", origfd: "<<chain.first->key.fd<<endl;
      */
      chain.first->key.chain.insert(id); // we can chain
      *fd=-1;                            // gets used in waitEvent / sendEvent later on
      return 1;
    }
  }

  int ret=t_udpclientsocks->getSocket(toaddr, fd);
  if(ret < 0)
    return ret;

  pident.fd=*fd;
  pident.id=id;

  t_fdm->addReadFD(*fd, handleUDPServerResponse, pident);
  ret = send(*fd, data, len, 0);

  int tmp = errno;

  if(ret < 0)
    t_udpclientsocks->returnSocket(*fd);

  errno = tmp; // this is for logging purposes only
  return ret;
}

// -1 is error, 0 is timeout, 1 is success
int arecvfrom(std::string& packet, int flags, const ComboAddress& fromaddr, size_t *d_len,
              uint16_t id, const DNSName& domain, uint16_t qtype, int fd, struct timeval* now)
{
  static optional<unsigned int> nearMissLimit;
  if(!nearMissLimit)
    nearMissLimit=::arg().asNum("spoof-nearmiss-max");

  PacketID pident;
  pident.fd=fd;
  pident.id=id;
  pident.domain=domain;
  pident.type = qtype;
  pident.remote=fromaddr;

  int ret=MT->waitEvent(pident, &packet, g_networkTimeoutMsec, now);

  /* -1 means error, 0 means timeout, 1 means a result from handleUDPServerResponse() which might still be an error */
  if(ret > 0) {
    /* handleUDPServerResponse() will close the socket for us no matter what */
    if(packet.empty()) // means "error"
      return -1;

    *d_len=packet.size();

    if(*nearMissLimit && pident.nearMisses > *nearMissLimit) {
      g_log<<Logger::Error<<"Too many ("<<pident.nearMisses<<" > "<<*nearMissLimit<<") bogus answers for '"<<domain<<"' from "<<fromaddr.toString()<<", assuming spoof attempt."<<endl;
      g_stats.spoofCount++;
      return -1;
    }
  }
  else {
    /* getting there means error or timeout, it's up to us to close the socket */
    if(fd >= 0)
      t_udpclientsocks->returnSocket(fd);
  }
  return ret;
}

static void writePid(void)
{
  if(!::arg().mustDo("write-pid"))
    return;
  ofstream of(s_pidfname.c_str(), std::ios_base::app);
  if(of)
    of<< Utility::getpid() <<endl;
  else {
    int err = errno;
    g_log << Logger::Error << "Writing pid for " << Utility::getpid() << " to " << s_pidfname << " failed: "
          << stringerror(err) << endl;
  }
}

uint16_t TCPConnection::s_maxInFlight;

TCPConnection::TCPConnection(int fd, const ComboAddress& addr) : data(2, 0), d_remote(addr), d_fd(fd)
{
  ++s_currentConnections;
  (*t_tcpClientCounts)[d_remote]++;
}

TCPConnection::~TCPConnection()
{
  try {
    if(closesocket(d_fd) < 0)
      g_log<<Logger::Error<<"Error closing socket for TCPConnection"<<endl;
  }
  catch(const PDNSException& e) {
    g_log<<Logger::Error<<"Error closing TCPConnection socket: "<<e.reason<<endl;
  }

  if(t_tcpClientCounts->count(d_remote) && !(*t_tcpClientCounts)[d_remote]--)
    t_tcpClientCounts->erase(d_remote);
  --s_currentConnections;
}

AtomicCounter TCPConnection::s_currentConnections;

static void handleRunningTCPQuestion(int fd, FDMultiplexer::funcparam_t& var);

// the idea is, only do things that depend on the *response* here. Incoming accounting is on incoming.
static void updateResponseStats(int res, const ComboAddress& remote, unsigned int packetsize, const DNSName* query, uint16_t qtype)
{
  if(packetsize > 1000 && t_largeanswerremotes)
    t_largeanswerremotes->push_back(remote);
  switch(res) {
  case RCode::ServFail:
    if(t_servfailremotes) {
      t_servfailremotes->push_back(remote);
      if(query && t_servfailqueryring) // packet cache
	t_servfailqueryring->push_back(make_pair(*query, qtype));
    }
    g_stats.servFails++;
    break;
  case RCode::NXDomain:
    g_stats.nxDomains++;
    break;
  case RCode::NoError:
    g_stats.noErrors++;
    break;
  }
}

static string makeLoginfo(const std::unique_ptr<DNSComboWriter>& dc)
try
{
  return "("+dc->d_mdp.d_qname.toLogString()+"/"+DNSRecordContent::NumberToType(dc->d_mdp.d_qtype)+" from "+(dc->getRemote())+")";
}
catch(...)
{
  return "Exception making error message for exception";
}

#ifdef HAVE_PROTOBUF
static void protobufLogQuery(uint8_t maskV4, uint8_t maskV6, const boost::uuids::uuid& uniqueId, const ComboAddress& remote, const ComboAddress& local, const Netmask& ednssubnet, bool tcp, uint16_t id, size_t len, const DNSName& qname, uint16_t qtype, uint16_t qclass, const std::vector<std::string>& policyTags, const std::string& requestorId, const std::string& deviceId, const std::string& deviceName)
{
  if (!t_protobufServers) {
    return;
  }

  Netmask requestorNM(remote, remote.sin4.sin_family == AF_INET ? maskV4 : maskV6);
  const ComboAddress& requestor = requestorNM.getMaskedNetwork();
  RecProtoBufMessage message(DNSProtoBufMessage::Query, uniqueId, &requestor, &local, qname, qtype, qclass, id, tcp, len);
  message.setServerIdentity(SyncRes::s_serverID);
  message.setEDNSSubnet(ednssubnet, ednssubnet.isIpv4() ? maskV4 : maskV6);
  message.setRequestorId(requestorId);
  message.setDeviceId(deviceId);
  message.setDeviceName(deviceName);

  if (!policyTags.empty()) {
    message.setPolicyTags(policyTags);
  }

//  cerr <<message.toDebugString()<<endl;
  std::string str;
  message.serialize(str);

  for (auto& server : *t_protobufServers) {
    server->queueData(str);
  }
}

static void protobufLogResponse(const RecProtoBufMessage& message)
{
  if (!t_protobufServers) {
    return;
  }

//  cerr <<message.toDebugString()<<endl;
  std::string str;
  message.serialize(str);

  for (auto& server : *t_protobufServers) {
    server->queueData(str);
  }
}
#endif

/**
 * Chases the CNAME provided by the PolicyCustom RPZ policy.
 *
 * @param spoofed: The DNSRecord that was created by the policy, should already be added to ret
 * @param qtype: The QType of the original query
 * @param sr: A SyncRes
 * @param res: An integer that will contain the RCODE of the lookup we do
 * @param ret: A vector of DNSRecords where the result of the CNAME chase should be appended to
 */
static void handleRPZCustom(const DNSRecord& spoofed, const QType& qtype, SyncRes& sr, int& res, vector<DNSRecord>& ret)
{
  if (spoofed.d_type == QType::CNAME) {
    bool oldWantsRPZ = sr.getWantsRPZ();
    sr.setWantsRPZ(false);
    vector<DNSRecord> ans;
    res = sr.beginResolve(DNSName(spoofed.d_content->getZoneRepresentation()), qtype, QClass::IN, ans);
    for (const auto& rec : ans) {
      if(rec.d_place == DNSResourceRecord::ANSWER) {
        ret.push_back(rec);
      }
    }
    // Reset the RPZ state of the SyncRes
    sr.setWantsRPZ(oldWantsRPZ);
  }
}

static bool addRecordToPacket(DNSPacketWriter& pw, const DNSRecord& rec, uint32_t& minTTL, uint32_t ttlCap, const uint16_t maxAnswerSize)
{
  pw.startRecord(rec.d_name, rec.d_type, (rec.d_ttl > ttlCap ? ttlCap : rec.d_ttl), rec.d_class, rec.d_place);

  if(rec.d_type != QType::OPT) // their TTL ain't real
    minTTL = min(minTTL, rec.d_ttl);

  rec.d_content->toPacket(pw);
  if(pw.size() > static_cast<size_t>(maxAnswerSize)) {
    pw.rollback();
    if(rec.d_place != DNSResourceRecord::ADDITIONAL) {
      pw.getHeader()->tc=1;
      pw.truncate();
    }
    return false;
  }

  return true;
}

#ifdef HAVE_PROTOBUF
static std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>> startProtobufServers(const ProtobufExportConfig& config)
{
  auto result = std::make_shared<std::vector<std::unique_ptr<RemoteLogger>>>();

  for (const auto& server : config.servers) {
    try {
      auto logger = make_unique<RemoteLogger>(server, config.timeout, 100*config.maxQueuedEntries, config.reconnectWaitTime, config.asyncConnect);
      logger->setLogQueries(config.logQueries);
      logger->setLogResponses(config.logResponses);
      result->emplace_back(std::move(logger));
    }
    catch(const std::exception& e) {
      g_log<<Logger::Error<<"Error while starting protobuf logger to '"<<server<<": "<<e.what()<<endl;
    }
    catch(const PDNSException& e) {
      g_log<<Logger::Error<<"Error while starting protobuf logger to '"<<server<<": "<<e.reason<<endl;
    }
  }

  return result;
}

static bool checkProtobufExport(LocalStateHolder<LuaConfigItems>& luaconfsLocal)
{
  if (!luaconfsLocal->protobufExportConfig.enabled) {
    if (t_protobufServers) {
      for (auto& server : *t_protobufServers) {
        server->stop();
      }
      t_protobufServers.reset();
    }

    return false;
  }

  /* if the server was not running, or if it was running according to a
     previous configuration */
  if (!t_protobufServers ||
      t_protobufServersGeneration < luaconfsLocal->generation) {

    if (t_protobufServers) {
      for (auto& server : *t_protobufServers) {
        server->stop();
      }
    }
    t_protobufServers.reset();

    t_protobufServers = startProtobufServers(luaconfsLocal->protobufExportConfig);
    t_protobufServersGeneration = luaconfsLocal->generation;
  }

  return true;
}

static bool checkOutgoingProtobufExport(LocalStateHolder<LuaConfigItems>& luaconfsLocal)
{
  if (!luaconfsLocal->outgoingProtobufExportConfig.enabled) {
    if (t_outgoingProtobufServers) {
      for (auto& server : *t_outgoingProtobufServers) {
        server->stop();
      }
    }
    t_outgoingProtobufServers.reset();

    return false;
  }

  /* if the server was not running, or if it was running according to a
     previous configuration */
  if (!t_outgoingProtobufServers ||
      t_outgoingProtobufServersGeneration < luaconfsLocal->generation) {

    if (t_outgoingProtobufServers) {
      for (auto& server : *t_outgoingProtobufServers) {
        server->stop();
      }
    }
    t_outgoingProtobufServers.reset();

    t_outgoingProtobufServers = startProtobufServers(luaconfsLocal->outgoingProtobufExportConfig);
    t_outgoingProtobufServersGeneration = luaconfsLocal->generation;
  }

  return true;
}

#ifdef HAVE_FSTRM

static std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>> startFrameStreamServers(const FrameStreamExportConfig& config)
{
  auto result = std::make_shared<std::vector<std::unique_ptr<FrameStreamLogger>>>();

  for (const auto& server : config.servers) {
    try {
      std::unordered_map<string,unsigned> options;
      options["bufferHint"] = config.bufferHint;
      options["flushTimeout"] = config.flushTimeout;
      options["inputQueueSize"] = config.inputQueueSize;
      options["outputQueueSize"] = config.outputQueueSize;
      options["queueNotifyThreshold"] = config.queueNotifyThreshold;
      options["reopenInterval"] = config.reopenInterval;
      FrameStreamLogger *fsl = nullptr;
      try {
        ComboAddress address(server);
        fsl = new FrameStreamLogger(address.sin4.sin_family, address.toStringWithPort(), true, options);
      }
      catch (const PDNSException& e) {
        fsl = new FrameStreamLogger(AF_UNIX, server, true, options);
      }
      fsl->setLogQueries(config.logQueries);
      fsl->setLogResponses(config.logResponses);
      result->emplace_back(fsl);
    }
    catch(const std::exception& e) {
      g_log<<Logger::Error<<"Error while starting dnstap framestream logger to '"<<server<<": "<<e.what()<<endl;
    }
    catch(const PDNSException& e) {
      g_log<<Logger::Error<<"Error while starting dnstap framestream logger to '"<<server<<": "<<e.reason<<endl;
    }
  }

  return result;
}

static bool checkFrameStreamExport(LocalStateHolder<LuaConfigItems>& luaconfsLocal)
{
  if (!luaconfsLocal->frameStreamExportConfig.enabled) {
    if (t_frameStreamServers) {
      // dt's take care of cleanup
      t_frameStreamServers.reset();
    }

    return false;
  }

  /* if the server was not running, or if it was running according to a
     previous configuration */
  if (!t_frameStreamServers ||
      t_frameStreamServersGeneration < luaconfsLocal->generation) {

    if (t_frameStreamServers) {
      // dt's take care of cleanup
      t_frameStreamServers.reset();
    }

    t_frameStreamServers = startFrameStreamServers(luaconfsLocal->frameStreamExportConfig);
    t_frameStreamServersGeneration = luaconfsLocal->generation;
  }

  return true;
}
#endif /* HAVE_FSTRM */
#endif /* HAVE_PROTOBUF */

#ifdef NOD_ENABLED
static bool nodCheckNewDomain(const DNSName& dname)
{
  static const QType qt(QType::A);
  static const uint16_t qc(QClass::IN);
  bool ret = false;
  // First check the (sub)domain isn't whitelisted for NOD purposes
  if (!g_nodDomainWL.check(dname)) {
    // Now check the NODDB (note this is probablistic so can have FNs/FPs)
    if (t_nodDBp && t_nodDBp->isNewDomain(dname)) {
      if (g_nodLog) {
        // This should probably log to a dedicated log file
        g_log<<Logger::Notice<<"Newly observed domain nod="<<dname.toLogString()<<endl;
      }
      if (!(g_nodLookupDomain.isRoot())) {
        // Send a DNS A query to <domain>.g_nodLookupDomain
        DNSName qname = dname;
        vector<DNSRecord> dummy;
        qname += g_nodLookupDomain;
        directResolve(qname, qt, qc, dummy);
      }
      ret = true;
    }
  }
  return ret;
}

static bool udrCheckUniqueDNSRecord(const DNSName& dname, uint16_t qtype, const DNSRecord& record)
{
  bool ret = false;
  if (record.d_place == DNSResourceRecord::ANSWER ||
      record.d_place == DNSResourceRecord::ADDITIONAL) {
    // Create a string that represent a triplet of (qname, qtype and RR[type, name, content])
    std::stringstream ss;
    ss << dname.toDNSStringLC() << ":" << qtype <<  ":" << qtype << ":" << record.d_type << ":" << record.d_name.toDNSStringLC() << ":" << record.d_content->getZoneRepresentation();
    if (t_udrDBp && t_udrDBp->isUniqueResponse(ss.str())) {
      if (g_udrLog) {  
        // This should also probably log to a dedicated file. 
        g_log<<Logger::Notice<<"Unique response observed: qname="<<dname.toLogString()<<" qtype="<<QType(qtype).getName()<< " rrtype=" << QType(record.d_type).getName() << " rrname=" << record.d_name.toLogString() << " rrcontent=" << record.d_content->getZoneRepresentation() << endl;
      }
      ret = true;
    }
  }
  return ret;
}
#endif /* NOD_ENABLED */

int followCNAMERecords(vector<DNSRecord>& ret, const QType& qtype)
{
  vector<DNSRecord> resolved;
  DNSName target;
  for(const DNSRecord& rr :  ret) {
    if(rr.d_type == QType::CNAME) {
      auto rec = getRR<CNAMERecordContent>(rr);
      if(rec) {
        target=rec->getTarget();
        break;
      }
    }
  }

  if(target.empty()) {
    return 0;
  }

  int rcode = directResolve(target, qtype, QClass::IN, resolved);

  for(DNSRecord& rr :  resolved) {
    ret.push_back(std::move(rr));
  }
  return rcode;
}

static void startDoResolve(void *p)
{
  auto dc=std::unique_ptr<DNSComboWriter>(reinterpret_cast<DNSComboWriter*>(p));
  try {
    if (t_queryring)
      t_queryring->push_back(make_pair(dc->d_mdp.d_qname, dc->d_mdp.d_qtype));

    uint16_t maxanswersize = dc->d_tcp ? 65535 : min(static_cast<uint16_t>(512), g_udpTruncationThreshold);
    EDNSOpts edo;
    std::vector<pair<uint16_t, string> > ednsOpts;
    bool variableAnswer = dc->d_variable;
    bool haveEDNS=false;
#ifdef NOD_ENABLED
    bool hasUDR = false;
#endif /* NOD_ENABLED */
    DNSPacketWriter::optvect_t returnedEdnsOptions; // Here we stuff all the options for the return packet
    uint8_t ednsExtRCode = 0;
    if(getEDNSOpts(dc->d_mdp, &edo)) {
      haveEDNS=true;
      if (edo.d_version != 0) {
        ednsExtRCode = ERCode::BADVERS;
      }

      if(!dc->d_tcp) {
        /* rfc6891 6.2.3:
           "Values lower than 512 MUST be treated as equal to 512."
        */
        maxanswersize = min(static_cast<uint16_t>(edo.d_packetsize >= 512 ? edo.d_packetsize : 512), g_udpTruncationThreshold);
      }
      ednsOpts = edo.d_options;
      maxanswersize -= 11; // EDNS header size

      for (const auto& o : edo.d_options) {
        if (o.first == EDNSOptionCode::ECS && g_useIncomingECS && !dc->d_ecsParsed) {
          dc->d_ecsFound = getEDNSSubnetOptsFromString(o.second, &dc->d_ednssubnet);
        } else if (o.first == EDNSOptionCode::NSID) {
          const static string mode_server_id = ::arg()["server-id"];
          if(mode_server_id != "disabled" && !mode_server_id.empty() &&
              maxanswersize > (2 + 2 + mode_server_id.size())) {
            returnedEdnsOptions.push_back(make_pair(EDNSOptionCode::NSID, mode_server_id));
            variableAnswer = true; // Can't packetcache an answer with NSID
            // Option Code and Option Length are both 2
            maxanswersize -= 2 + 2 + mode_server_id.size();
          }
        }
      }
    }
    /* perhaps there was no EDNS or no ECS but by now we looked */
    dc->d_ecsParsed = true;
    vector<DNSRecord> ret;
    vector<uint8_t> packet;

    auto luaconfsLocal = g_luaconfs.getLocal();
    // Used to tell syncres later on if we should apply NSDNAME and NSIP RPZ triggers for this query
    bool wantsRPZ(true);
    boost::optional<RecProtoBufMessage> pbMessage(boost::none);
#ifdef HAVE_PROTOBUF
    if (checkProtobufExport(luaconfsLocal)) {
      Netmask requestorNM(dc->d_source, dc->d_source.sin4.sin_family == AF_INET ? luaconfsLocal->protobufMaskV4 : luaconfsLocal->protobufMaskV6);
      const ComboAddress& requestor = requestorNM.getMaskedNetwork();
      pbMessage = RecProtoBufMessage(RecProtoBufMessage::Response, dc->d_uuid, &requestor, &dc->d_destination, dc->d_mdp.d_qname, dc->d_mdp.d_qtype, dc->d_mdp.d_qclass, dc->d_mdp.d_header.id, dc->d_tcp, 0);
      pbMessage->setServerIdentity(SyncRes::s_serverID);
      pbMessage->setEDNSSubnet(dc->d_ednssubnet.source, dc->d_ednssubnet.source.isIpv4() ? luaconfsLocal->protobufMaskV4 : luaconfsLocal->protobufMaskV6);
    }
#endif /* HAVE_PROTOBUF */

#ifdef HAVE_FSTRM
    checkFrameStreamExport(luaconfsLocal);
#endif

    DNSPacketWriter pw(packet, dc->d_mdp.d_qname, dc->d_mdp.d_qtype, dc->d_mdp.d_qclass);

    pw.getHeader()->aa=0;
    pw.getHeader()->ra=1;
    pw.getHeader()->qr=1;
    pw.getHeader()->tc=0;
    pw.getHeader()->id=dc->d_mdp.d_header.id;
    pw.getHeader()->rd=dc->d_mdp.d_header.rd;
    pw.getHeader()->cd=dc->d_mdp.d_header.cd;

    /* This is the lowest TTL seen in the records of the response,
       so we can't cache it for longer than this value.
       If we have a TTL cap, this value can't be larger than the
       cap no matter what. */
    uint32_t minTTL = dc->d_ttlCap;

    SyncRes sr(dc->d_now);
    sr.setId(MT->getTid());

    bool DNSSECOK=false;
    if(t_pdl) {
      sr.setLuaEngine(t_pdl);
    }
    if(g_dnssecmode != DNSSECMode::Off) {
      sr.setDoDNSSEC(true);

      // Does the requestor want DNSSEC records?
      if(edo.d_extFlags & EDNSOpts::DNSSECOK) {
        DNSSECOK=true;
        g_stats.dnssecQueries++;
      }
      if (dc->d_mdp.d_header.cd) {
        /* Per rfc6840 section 5.9, "When processing a request with
           the Checking Disabled (CD) bit set, a resolver SHOULD attempt
           to return all response data, even data that has failed DNSSEC
           validation. */
        ++g_stats.dnssecCheckDisabledQueries;
      }
      if (dc->d_mdp.d_header.ad) {
        /* Per rfc6840 section 5.7, "the AD bit in a query as a signal
           indicating that the requester understands and is interested in the
           value of the AD bit in the response.  This allows a requester to
           indicate that it understands the AD bit without also requesting
           DNSSEC data via the DO bit. */
        ++g_stats.dnssecAuthenticDataQueries;
      }
    } else {
      // Ignore the client-set CD flag
      pw.getHeader()->cd=0;
    }
    sr.setDNSSECValidationRequested(g_dnssecmode == DNSSECMode::ValidateAll || g_dnssecmode==DNSSECMode::ValidateForLog || ((dc->d_mdp.d_header.ad || DNSSECOK) && g_dnssecmode==DNSSECMode::Process));

#ifdef HAVE_PROTOBUF
    sr.setInitialRequestId(dc->d_uuid);
    sr.setOutgoingProtobufServers(t_outgoingProtobufServers);
#endif
#ifdef HAVE_FSTRM
    sr.setFrameStreamServers(t_frameStreamServers);
#endif
    sr.setQuerySource(dc->d_remote, g_useIncomingECS && !dc->d_ednssubnet.source.empty() ? boost::optional<const EDNSSubnetOpts&>(dc->d_ednssubnet) : boost::none);

    bool tracedQuery=false; // we could consider letting Lua know about this too
    bool shouldNotValidate = false;

    /* preresolve expects res (dq.rcode) to be set to RCode::NoError by default */
    int res = RCode::NoError;

    DNSFilterEngine::Policy appliedPolicy;
    std::vector<DNSRecord> spoofed;
    RecursorLua4::DNSQuestion dq(dc->d_source, dc->d_destination, dc->d_mdp.d_qname, dc->d_mdp.d_qtype, dc->d_tcp, variableAnswer, wantsRPZ, dc->d_logResponse);
    dq.ednsFlags = &edo.d_extFlags;
    dq.ednsOptions = &ednsOpts;
    dq.tag = dc->d_tag;
    dq.discardedPolicies = &sr.d_discardedPolicies;
    dq.policyTags = &dc->d_policyTags;
    dq.appliedPolicy = &appliedPolicy;
    dq.currentRecords = &ret;
    dq.dh = &dc->d_mdp.d_header;
    dq.data = dc->d_data;
#ifdef HAVE_PROTOBUF
    dq.requestorId = dc->d_requestorId;
    dq.deviceId = dc->d_deviceId;
    dq.deviceName = dc->d_deviceName;
#endif

    if(ednsExtRCode != 0) {
      goto sendit;
    }

    if(dc->d_mdp.d_qtype==QType::ANY && !dc->d_tcp && g_anyToTcp) {
      pw.getHeader()->tc = 1;
      res = 0;
      variableAnswer = true;
      goto sendit;
    }

    if(t_traceRegex && t_traceRegex->match(dc->d_mdp.d_qname.toString())) {
      sr.setLogMode(SyncRes::Store);
      tracedQuery=true;
    }

    if(!g_quiet || tracedQuery) {
      g_log<<Logger::Warning<<t_id<<" ["<<MT->getTid()<<"/"<<MT->numProcesses()<<"] " << (dc->d_tcp ? "TCP " : "") << "question for '"<<dc->d_mdp.d_qname<<"|"
       <<DNSRecordContent::NumberToType(dc->d_mdp.d_qtype)<<"' from "<<dc->getRemote();
      if(!dc->d_ednssubnet.source.empty()) {
        g_log<<" (ecs "<<dc->d_ednssubnet.source.toString()<<")";
      }
      g_log<<endl;
    }

    if(!dc->d_mdp.d_header.rd) {
      sr.setCacheOnly();
    }

    if (dc->d_rcode != boost::none) {
      /* we have a response ready to go, most likely from gettag_ffi */
      ret = std::move(dc->d_records);
      res = *dc->d_rcode;
      if (res == RCode::NoError && dc->d_followCNAMERecords) {
        res = followCNAMERecords(ret, QType(dc->d_mdp.d_qtype));
      }
      goto haveAnswer;
    }

    if (t_pdl) {
      t_pdl->prerpz(dq, res);
    }

    // Check if the query has a policy attached to it
    if (wantsRPZ) {
      appliedPolicy = luaconfsLocal->dfe.getQueryPolicy(dc->d_mdp.d_qname, dc->d_source, sr.d_discardedPolicies);
    }

    // if there is a RecursorLua active, and it 'took' the query in preResolve, we don't launch beginResolve
    if(!t_pdl || !t_pdl->preresolve(dq, res)) {

      sr.setWantsRPZ(wantsRPZ);
      if(wantsRPZ) {
        switch(appliedPolicy.d_kind) {
          case DNSFilterEngine::PolicyKind::NoAction:
            break;
          case DNSFilterEngine::PolicyKind::Drop:
            g_stats.policyDrops++;
            g_stats.policyResults[appliedPolicy.d_kind]++;
            return; 
          case DNSFilterEngine::PolicyKind::NXDOMAIN:
            g_stats.policyResults[appliedPolicy.d_kind]++;
            res=RCode::NXDomain;
            goto haveAnswer;
          case DNSFilterEngine::PolicyKind::NODATA:
            g_stats.policyResults[appliedPolicy.d_kind]++;
            res=RCode::NoError;
            goto haveAnswer;
          case DNSFilterEngine::PolicyKind::Custom:
            g_stats.policyResults[appliedPolicy.d_kind]++;
            res=RCode::NoError;
            spoofed=appliedPolicy.getCustomRecords(dc->d_mdp.d_qname, dc->d_mdp.d_qtype);
            for (const auto& dr : spoofed) {
              ret.push_back(dr);
              handleRPZCustom(dr, QType(dc->d_mdp.d_qtype), sr, res, ret);
            }
            goto haveAnswer;
          case DNSFilterEngine::PolicyKind::Truncate:
            if(!dc->d_tcp) {
              g_stats.policyResults[appliedPolicy.d_kind]++;
              res=RCode::NoError;	
              pw.getHeader()->tc=1;
              goto haveAnswer;
            }
            break;
        }
      }

      // Query got not handled for QNAME Policy reasons, now actually go out to find an answer
      try {
        res = sr.beginResolve(dc->d_mdp.d_qname, QType(dc->d_mdp.d_qtype), dc->d_mdp.d_qclass, ret);
        shouldNotValidate = sr.wasOutOfBand();
      }
      catch(ImmediateServFailException &e) {
        if(g_logCommonErrors)
          g_log<<Logger::Notice<<"Sending SERVFAIL to "<<dc->getRemote()<<" during resolve of '"<<dc->d_mdp.d_qname<<"' because: "<<e.reason<<endl;
        res = RCode::ServFail;
      }

      dq.validationState = sr.getValidationState();

      // During lookup, an NSDNAME or NSIP trigger was hit in RPZ
      if (res == -2) { // XXX This block should be macro'd, it is repeated post-resolve.
        appliedPolicy = sr.d_appliedPolicy;
        g_stats.policyResults[appliedPolicy.d_kind]++;
        switch(appliedPolicy.d_kind) {
          case DNSFilterEngine::PolicyKind::NoAction: // This can never happen
            throw PDNSException("NoAction policy returned while a NSDNAME or NSIP trigger was hit");
          case DNSFilterEngine::PolicyKind::Drop:
            g_stats.policyDrops++;
            return;
          case DNSFilterEngine::PolicyKind::NXDOMAIN:
            ret.clear();
            res=RCode::NXDomain;
            goto haveAnswer;

          case DNSFilterEngine::PolicyKind::NODATA:
            ret.clear();
            res=RCode::NoError;
            goto haveAnswer;

          case DNSFilterEngine::PolicyKind::Truncate:
            if(!dc->d_tcp) {
              ret.clear();
              res=RCode::NoError;
              pw.getHeader()->tc=1;
              goto haveAnswer;
            }
            break;

          case DNSFilterEngine::PolicyKind::Custom:
            ret.clear();
            res=RCode::NoError;
            spoofed=appliedPolicy.getCustomRecords(dc->d_mdp.d_qname, dc->d_mdp.d_qtype);
            for (const auto& dr : spoofed) {
              ret.push_back(dr);
              handleRPZCustom(dr, QType(dc->d_mdp.d_qtype), sr, res, ret);
            }
            goto haveAnswer;
        }
      }

      if (wantsRPZ) {
        appliedPolicy = luaconfsLocal->dfe.getPostPolicy(ret, sr.d_discardedPolicies);
      }

      if(t_pdl) {
        if(res == RCode::NoError) {
	        auto i=ret.cbegin();
                for(; i!= ret.cend(); ++i)
                  if(i->d_type == dc->d_mdp.d_qtype && i->d_place == DNSResourceRecord::ANSWER)
                          break;
                if(i == ret.cend() && t_pdl->nodata(dq, res))
                  shouldNotValidate = true;

	}
	else if(res == RCode::NXDomain && t_pdl->nxdomain(dq, res))
          shouldNotValidate = true;

	if(t_pdl->postresolve(dq, res))
          shouldNotValidate = true;
      }

      if (wantsRPZ) { //XXX This block is repeated, see above
        g_stats.policyResults[appliedPolicy.d_kind]++;
        switch(appliedPolicy.d_kind) {
          case DNSFilterEngine::PolicyKind::NoAction:
            break;
          case DNSFilterEngine::PolicyKind::Drop:
            g_stats.policyDrops++;
            return; 
          case DNSFilterEngine::PolicyKind::NXDOMAIN:
            ret.clear();
            res=RCode::NXDomain;
            goto haveAnswer;

          case DNSFilterEngine::PolicyKind::NODATA:
            ret.clear();
            res=RCode::NoError;
            goto haveAnswer;

          case DNSFilterEngine::PolicyKind::Truncate:
            if(!dc->d_tcp) {
              ret.clear();
              res=RCode::NoError;
              pw.getHeader()->tc=1;
              goto haveAnswer;
            }
            break;

          case DNSFilterEngine::PolicyKind::Custom:
            ret.clear();
            res=RCode::NoError;
            spoofed=appliedPolicy.getCustomRecords(dc->d_mdp.d_qname, dc->d_mdp.d_qtype);
            for (const auto& dr : spoofed) {
              ret.push_back(dr);
              handleRPZCustom(dr, QType(dc->d_mdp.d_qtype), sr, res, ret);
            }
            goto haveAnswer;
        }
      }
    }
  haveAnswer:;
    if(res == PolicyDecision::DROP) {
      g_stats.policyDrops++;
      return;
    }
    if(tracedQuery || res == -1 || res == RCode::ServFail || pw.getHeader()->rcode == RCode::ServFail)
    { 
      string trace(sr.getTrace());
      if(!trace.empty()) {
        vector<string> lines;
        boost::split(lines, trace, boost::is_any_of("\n"));
        for(const string& line : lines) {
          if(!line.empty())
            g_log<<Logger::Warning<< line << endl;
        }
      }
    }

    if(res == -1) {
      pw.getHeader()->rcode=RCode::ServFail;
      // no commit here, because no record
      g_stats.servFails++;
    }
    else {
      pw.getHeader()->rcode=res;

      // Does the validation mode or query demand validation?
      if(!shouldNotValidate && sr.isDNSSECValidationRequested()) {
        try {
          if(sr.doLog()) {
            g_log<<Logger::Warning<<"Starting validation of answer to "<<dc->d_mdp.d_qname<<"|"<<QType(dc->d_mdp.d_qtype).getName()<<" for "<<dc->getRemote()<<endl;
          }

          auto state = sr.getValidationState();

          if(state == Secure) {
            if(sr.doLog()) {
              g_log<<Logger::Warning<<"Answer to "<<dc->d_mdp.d_qname<<"|"<<QType(dc->d_mdp.d_qtype).getName()<<" for "<<dc->getRemote()<<" validates correctly"<<endl;
            }
            
            // Is the query source interested in the value of the ad-bit?
            if (dc->d_mdp.d_header.ad || DNSSECOK)
              pw.getHeader()->ad=1;
          }
          else if(state == Insecure) {
            if(sr.doLog()) {
              g_log<<Logger::Warning<<"Answer to "<<dc->d_mdp.d_qname<<"|"<<QType(dc->d_mdp.d_qtype).getName()<<" for "<<dc->getRemote()<<" validates as Insecure"<<endl;
            }
            
            pw.getHeader()->ad=0;
          }
          else if(state == Bogus) {
            if(t_bogusremotes)
              t_bogusremotes->push_back(dc->d_source);
            if(t_bogusqueryring)
              t_bogusqueryring->push_back(make_pair(dc->d_mdp.d_qname, dc->d_mdp.d_qtype));
            if(g_dnssecLogBogus || sr.doLog() || g_dnssecmode == DNSSECMode::ValidateForLog) {
              g_log<<Logger::Warning<<"Answer to "<<dc->d_mdp.d_qname<<"|"<<QType(dc->d_mdp.d_qtype).getName()<<" for "<<dc->getRemote()<<" validates as Bogus"<<endl;
            }
            
            // Does the query or validation mode sending out a SERVFAIL on validation errors?
            if(!pw.getHeader()->cd && (g_dnssecmode == DNSSECMode::ValidateAll || dc->d_mdp.d_header.ad || DNSSECOK)) {
              if(sr.doLog()) {
                g_log<<Logger::Warning<<"Sending out SERVFAIL for "<<dc->d_mdp.d_qname<<"|"<<QType(dc->d_mdp.d_qtype).getName()<<" because recursor or query demands it for Bogus results"<<endl;
              }
              
              pw.getHeader()->rcode=RCode::ServFail;
              goto sendit;
            } else {
              if(sr.doLog()) {
                g_log<<Logger::Warning<<"Not sending out SERVFAIL for "<<dc->d_mdp.d_qname<<"|"<<QType(dc->d_mdp.d_qtype).getName()<<" Bogus validation since neither config nor query demands this"<<endl;
              }
            }
          }
        }
        catch(ImmediateServFailException &e) {
          if(g_logCommonErrors)
            g_log<<Logger::Notice<<"Sending SERVFAIL to "<<dc->getRemote()<<" during validation of '"<<dc->d_mdp.d_qname<<"|"<<QType(dc->d_mdp.d_qtype).getName()<<"' because: "<<e.reason<<endl;
          pw.getHeader()->rcode=RCode::ServFail;
          goto sendit;
        }
      }

      if(ret.size()) {
        orderAndShuffle(ret);
	if(auto sl = luaconfsLocal->sortlist.getOrderCmp(dc->d_source)) {
	  stable_sort(ret.begin(), ret.end(), *sl);
	  variableAnswer=true;
	}
      }

      bool needCommit = false;
      for(auto i=ret.cbegin(); i!=ret.cend(); ++i) {
        if( ! DNSSECOK &&
            ( i->d_type == QType::NSEC3 ||
              (
                ( i->d_type == QType::RRSIG || i->d_type==QType::NSEC ) &&
                (
                  ( dc->d_mdp.d_qtype != i->d_type &&  dc->d_mdp.d_qtype != QType::ANY ) ||
                  i->d_place != DNSResourceRecord::ANSWER
                )
              )
            )
          ) {
          continue;
        }

        if (!addRecordToPacket(pw, *i, minTTL, dc->d_ttlCap, maxanswersize)) {
          needCommit = false;
          break;
        }
        needCommit = true;

#ifdef NOD_ENABLED
	bool udr = false;
	if (g_udrEnabled) {
	  udr = udrCheckUniqueDNSRecord(dc->d_mdp.d_qname, dc->d_mdp.d_qtype, *i);
          if (!hasUDR && udr)
            hasUDR = true;
	}
#endif /* NOD ENABLED */    

#ifdef HAVE_PROTOBUF
        if (t_protobufServers) {
#ifdef NOD_ENABLED
          pbMessage->addRR(*i, luaconfsLocal->protobufExportConfig.exportTypes, udr);
#else
          pbMessage->addRR(*i, luaconfsLocal->protobufExportConfig.exportTypes);
#endif /* NOD_ENABLED */
        }
#endif
      }
      if(needCommit)
	pw.commit();
    }
  sendit:;

    if(g_useIncomingECS && dc->d_ecsFound && !sr.wasVariable() && !variableAnswer) {
      //      cerr<<"Stuffing in a 0 scope because answer is static"<<endl;
      EDNSSubnetOpts eo;
      eo.source = dc->d_ednssubnet.source;
      ComboAddress sa;
      sa.reset();
      sa.sin4.sin_family = eo.source.getNetwork().sin4.sin_family;
      eo.scope = Netmask(sa, 0);

      returnedEdnsOptions.push_back(make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(eo)));
    }

    if (haveEDNS) {
      /* we try to add the EDNS OPT RR even for truncated answers,
         as rfc6891 states:
         "The minimal response MUST be the DNS header, question section, and an
         OPT record.  This MUST also occur when a truncated response (using
         the DNS header's TC bit) is returned."
      */
      pw.addOpt(512, ednsExtRCode, DNSSECOK ? EDNSOpts::DNSSECOK : 0, returnedEdnsOptions);
      pw.commit();
    }

    g_rs.submitResponse(dc->d_mdp.d_qtype, packet.size(), !dc->d_tcp);
    updateResponseStats(res, dc->d_source, packet.size(), &dc->d_mdp.d_qname, dc->d_mdp.d_qtype);
#ifdef NOD_ENABLED
    bool nod = false;
    if (g_nodEnabled) {
      if (nodCheckNewDomain(dc->d_mdp.d_qname))
        nod = true;
    }
#endif /* NOD_ENABLED */
#ifdef HAVE_PROTOBUF
    if (t_protobufServers && !(luaconfsLocal->protobufExportConfig.taggedOnly && (!appliedPolicy.d_name || appliedPolicy.d_name->empty()) && dc->d_policyTags.empty())) {
      pbMessage->setBytes(packet.size());
      pbMessage->setResponseCode(pw.getHeader()->rcode);
      if (appliedPolicy.d_name) {
        pbMessage->setAppliedPolicy(*appliedPolicy.d_name);
        pbMessage->setAppliedPolicyType(appliedPolicy.d_type);
      }
      pbMessage->setPolicyTags(dc->d_policyTags);
      if (g_useKernelTimestamp && dc->d_kernelTimestamp.tv_sec) {
        pbMessage->setQueryTime(dc->d_kernelTimestamp.tv_sec, dc->d_kernelTimestamp.tv_usec);
      }
      else {
        pbMessage->setQueryTime(dc->d_now.tv_sec, dc->d_now.tv_usec);
      }
      pbMessage->setRequestorId(dq.requestorId);
      pbMessage->setDeviceId(dq.deviceId);
      pbMessage->setDeviceName(dq.deviceName);
#ifdef NOD_ENABLED
      if (g_nodEnabled) {
        if (nod) {
	  pbMessage->setNOD(true);
          pbMessage->addPolicyTag(g_nod_pbtag);
        }
        if (hasUDR) {
          pbMessage->addPolicyTag(g_udr_pbtag);
        }
      }
#endif /* NOD_ENABLED */
      if (dc->d_logResponse) {
        protobufLogResponse(*pbMessage);
      }
#ifdef NOD_ENABLED
      if (g_nodEnabled) {
        pbMessage->setNOD(false);
        pbMessage->clearUDR();
        if (nod)
          pbMessage->removePolicyTag(g_nod_pbtag);
        if (hasUDR)
          pbMessage->removePolicyTag(g_udr_pbtag);
      }
#endif /* NOD_ENABLED */
    }
#endif
    if(!dc->d_tcp) {
      struct msghdr msgh;
      struct iovec iov;
      cmsgbuf_aligned cbuf;
      fillMSGHdr(&msgh, &iov, &cbuf, 0, (char*)&*packet.begin(), packet.size(), &dc->d_remote);
      msgh.msg_control=NULL;

      if(g_fromtosockets.count(dc->d_socket)) {
        addCMsgSrcAddr(&msgh, &cbuf, &dc->d_local, 0);
      }
      if(sendmsg(dc->d_socket, &msgh, 0) < 0 && g_logCommonErrors) {
        int err = errno;
        g_log << Logger::Warning << "Sending UDP reply to client " << dc->getRemote() << " failed with: "
              << strerror(err) << endl;
      }

      if(variableAnswer || sr.wasVariable()) {
        g_stats.variableResponses++;
      }
      if(!SyncRes::s_nopacketcache && !variableAnswer && !sr.wasVariable() ) {
        t_packetCache->insertResponsePacket(dc->d_tag, dc->d_qhash, std::move(dc->d_query), dc->d_mdp.d_qname, dc->d_mdp.d_qtype, dc->d_mdp.d_qclass,
                                            string((const char*)&*packet.begin(), packet.size()),
                                            g_now.tv_sec,
                                            pw.getHeader()->rcode == RCode::ServFail ? SyncRes::s_packetcacheservfailttl :
                                            min(minTTL,SyncRes::s_packetcachettl),
                                            dq.validationState,
                                            dc->d_ecsBegin,
                                            dc->d_ecsEnd,
                                            std::move(pbMessage));
      }
      //      else cerr<<"Not putting in packet cache: "<<sr.wasVariable()<<endl;
    }
    else {
      char buf[2];
      buf[0]=packet.size()/256;
      buf[1]=packet.size()%256;

      Utility::iovec iov[2];

      iov[0].iov_base=(void*)buf;              iov[0].iov_len=2;
      iov[1].iov_base=(void*)&*packet.begin(); iov[1].iov_len = packet.size();

      int wret=Utility::writev(dc->d_socket, iov, 2);
      bool hadError=true;

      if(wret == 0)
        g_log<<Logger::Error<<"EOF writing TCP answer to "<<dc->getRemote()<<endl;
      else if(wret < 0 ) {
        int err = errno;
        g_log << Logger::Error << "Error writing TCP answer to " << dc->getRemote() << ": " << strerror(err) << endl;
      } else if((unsigned int)wret != 2 + packet.size())
        g_log<<Logger::Error<<"Oops, partial answer sent to "<<dc->getRemote()<<" for "<<dc->d_mdp.d_qname<<" (size="<< (2 + packet.size()) <<", sent "<<wret<<")"<<endl;
      else
        hadError=false;

      // update tcp connection status, closing if needed and doing the fd multiplexer accounting
      if  (dc->d_tcpConnection->d_requestsInFlight > 0) {
        dc->d_tcpConnection->d_requestsInFlight--;
      }

      // In the code below, we try to remove the fd from the set, but
      // we don't know if another mthread already did the remove, so we can get a
      // "Tried to remove unlisted fd" exception.  Not that an inflight < limit test
      // will not work since we do not know if the other mthread got an error or not.
      if(hadError) {
        try {
          t_fdm->removeReadFD(dc->d_socket);
        }
        catch (FDMultiplexerException &) {
        }
        dc->d_socket = -1;
      }
      else {
        dc->d_tcpConnection->queriesCount++;
        if (g_tcpMaxQueriesPerConn && dc->d_tcpConnection->queriesCount >= g_tcpMaxQueriesPerConn) {
          try {
            t_fdm->removeReadFD(dc->d_socket);
          }
          catch (FDMultiplexerException &) {
          }
          dc->d_socket = -1;
        }
        else {
          Utility::gettimeofday(&g_now, 0); // needs to be updated
          struct timeval ttd = g_now;
          // If we cross from max to max-1 in flight requests, the fd was not listened to, add it back
          if (dc->d_tcpConnection->d_requestsInFlight == TCPConnection::s_maxInFlight - 1) {
            // A read error might have happened. If we add the fd back, it will most likely error again.
            // This is not a big issue, the next handleTCPClientReadable() will see another read error
            // and take action.
            ttd.tv_sec += g_tcpTimeout;
            t_fdm->addReadFD(dc->d_socket, handleRunningTCPQuestion, dc->d_tcpConnection, &ttd);
          } else {
            // fd might have been removed by read error code, so expect an exception
            try {
              t_fdm->setReadTTD(dc->d_socket, ttd, g_tcpTimeout);
            }
            catch (FDMultiplexerException &) {
            }
          }
        }
      }
    }
    float spent=makeFloat(sr.getNow()-dc->d_now);
    if(!g_quiet) {
      g_log<<Logger::Error<<t_id<<" ["<<MT->getTid()<<"/"<<MT->numProcesses()<<"] answer to "<<(dc->d_mdp.d_header.rd?"":"non-rd ")<<"question '"<<dc->d_mdp.d_qname<<"|"<<DNSRecordContent::NumberToType(dc->d_mdp.d_qtype);
      g_log<<"': "<<ntohs(pw.getHeader()->ancount)<<" answers, "<<ntohs(pw.getHeader()->arcount)<<" additional, took "<<sr.d_outqueries<<" packets, "<<
	sr.d_totUsec/1000.0<<" netw ms, "<< spent*1000.0<<" tot ms, "<<
	sr.d_throttledqueries<<" throttled, "<<sr.d_timeouts<<" timeouts, "<<sr.d_tcpoutqueries<<" tcp connections, rcode="<< res;

      if(!shouldNotValidate && sr.isDNSSECValidationRequested()) {
	g_log<< ", dnssec="<<vStates[sr.getValidationState()];
      }
	
      g_log<<endl;

    }

    if (sr.d_outqueries || sr.d_authzonequeries) {
      t_RC->cacheMisses++;
    }
    else {
      t_RC->cacheHits++;
    }

    if(spent < 0.001)
      g_stats.answers0_1++;
    else if(spent < 0.010)
      g_stats.answers1_10++;
    else if(spent < 0.1)
      g_stats.answers10_100++;
    else if(spent < 1.0)
      g_stats.answers100_1000++;
    else
      g_stats.answersSlow++;

    uint64_t newLat=(uint64_t)(spent*1000000);
    newLat = min(newLat,(uint64_t)(((uint64_t) g_networkTimeoutMsec)*1000)); // outliers of several minutes exist..
    g_stats.avgLatencyUsec=(1-1.0/g_latencyStatSize)*g_stats.avgLatencyUsec + (float)newLat/g_latencyStatSize;
    // no worries, we do this for packet cache hits elsewhere

    auto ourtime = 1000.0*spent-sr.d_totUsec/1000.0; // in msec
    if(ourtime < 1)
      g_stats.ourtime0_1++;
    else if(ourtime < 2)
      g_stats.ourtime1_2++;
    else if(ourtime < 4)
      g_stats.ourtime2_4++;
    else if(ourtime < 8)
      g_stats.ourtime4_8++;
    else if(ourtime < 16)
      g_stats.ourtime8_16++;
    else if(ourtime < 32)
      g_stats.ourtime16_32++;
    else {
      //      cerr<<"SLOW: "<<ourtime<<"ms -> "<<dc->d_mdp.d_qname<<"|"<<DNSRecordContent::NumberToType(dc->d_mdp.d_qtype)<<endl;
      g_stats.ourtimeSlow++;
    }
    if(ourtime >= 0.0) {
      newLat=ourtime*1000; // usec
      g_stats.avgLatencyOursUsec=(1-1.0/g_latencyStatSize)*g_stats.avgLatencyOursUsec + (float)newLat/g_latencyStatSize;
    }
    //    cout<<dc->d_mdp.d_qname<<"\t"<<MT->getUsec()<<"\t"<<sr.d_outqueries<<endl;
  }
  catch(PDNSException &ae) {
    g_log<<Logger::Error<<"startDoResolve problem "<<makeLoginfo(dc)<<": "<<ae.reason<<endl;
  }
  catch(const MOADNSException &mde) {
    g_log<<Logger::Error<<"DNS parser error "<<makeLoginfo(dc) <<": "<<dc->d_mdp.d_qname<<", "<<mde.what()<<endl;
  }
  catch(std::exception& e) {
    g_log<<Logger::Error<<"STL error "<< makeLoginfo(dc)<<": "<<e.what();

    // Luawrapper nests the exception from Lua, so we unnest it here
    try {
        std::rethrow_if_nested(e);
    } catch(const std::exception& ne) {
        g_log<<". Extra info: "<<ne.what();
    } catch(...) {}

    g_log<<endl;
  }
  catch(...) {
    g_log<<Logger::Error<<"Any other exception in a resolver context "<< makeLoginfo(dc) <<endl;
  }

  g_stats.maxMThreadStackUsage = max(MT->getMaxStackUsage(), g_stats.maxMThreadStackUsage);
}

static void makeControlChannelSocket(int processNum=-1)
{
  string sockname=::arg()["socket-dir"]+"/"+s_programname;
  if(processNum >= 0)
    sockname += "."+std::to_string(processNum);
  sockname+=".controlsocket";
  s_rcc.listen(sockname);

  int sockowner = -1;
  int sockgroup = -1;

  if (!::arg().isEmpty("socket-group"))
    sockgroup=::arg().asGid("socket-group");
  if (!::arg().isEmpty("socket-owner"))
    sockowner=::arg().asUid("socket-owner");

  if (sockgroup > -1 || sockowner > -1) {
    if(chown(sockname.c_str(), sockowner, sockgroup) < 0) {
      unixDie("Failed to chown control socket");
    }
  }

  // do mode change if socket-mode is given
  if(!::arg().isEmpty("socket-mode")) {
    mode_t sockmode=::arg().asMode("socket-mode");
    if(chmod(sockname.c_str(), sockmode) < 0) {
      unixDie("Failed to chmod control socket");
    }
  }
}

static void getQNameAndSubnet(const std::string& question, DNSName* dnsname, uint16_t* qtype, uint16_t* qclass,
                              bool& foundECS, EDNSSubnetOpts* ednssubnet, EDNSOptionViewMap* options,
                              bool& foundXPF, ComboAddress* xpfSource, ComboAddress* xpfDest)
{
  const bool lookForXPF = xpfSource != nullptr && g_xpfRRCode != 0;
  const bool lookForECS = ednssubnet != nullptr;
  const struct dnsheader* dh = reinterpret_cast<const struct dnsheader*>(question.c_str());
  size_t questionLen = question.length();
  unsigned int consumed=0;
  *dnsname=DNSName(question.c_str(), questionLen, sizeof(dnsheader), false, qtype, qclass, &consumed);

  size_t pos= sizeof(dnsheader)+consumed+4;
  const size_t headerSize = /* root */ 1 + sizeof(dnsrecordheader);
  const uint16_t arcount = ntohs(dh->arcount);

  for (uint16_t arpos = 0; arpos < arcount && questionLen > (pos + headerSize) && ((lookForECS && !foundECS) || (lookForXPF && !foundXPF)); arpos++) {
    if (question.at(pos) != 0) {
      /* not an OPT or a XPF, bye. */
      return;
    }

    pos += 1;
    const dnsrecordheader* drh = reinterpret_cast<const dnsrecordheader*>(&question.at(pos));
    pos += sizeof(dnsrecordheader);

    if (pos >= questionLen) {
      return;
    }

    /* OPT root label (1) followed by type (2) */
    if(lookForECS && ntohs(drh->d_type) == QType::OPT) {
      if (!options) {
        char* ecsStart = nullptr;
        size_t ecsLen = 0;
        /* we need to pass the record len */
        int res = getEDNSOption(const_cast<char*>(reinterpret_cast<const char*>(&question.at(pos - sizeof(drh->d_clen)))), questionLen - pos + sizeof(drh->d_clen), EDNSOptionCode::ECS, &ecsStart, &ecsLen);
        if (res == 0 && ecsLen > 4) {
          EDNSSubnetOpts eso;
          if(getEDNSSubnetOptsFromString(ecsStart + 4, ecsLen - 4, &eso)) {
            *ednssubnet=eso;
            foundECS = true;
          }
        }
      }
      else {
        /* we need to pass the record len */
        int res = getEDNSOptions(reinterpret_cast<const char*>(&question.at(pos -sizeof(drh->d_clen))), questionLen - pos + (sizeof(drh->d_clen)), *options);
        if (res == 0) {
          const auto& it = options->find(EDNSOptionCode::ECS);
          if (it != options->end() && !it->second.values.empty() && it->second.values.at(0).content != nullptr && it->second.values.at(0).size > 0) {
            EDNSSubnetOpts eso;
            if(getEDNSSubnetOptsFromString(it->second.values.at(0).content, it->second.values.at(0).size, &eso)) {
              *ednssubnet=eso;
              foundECS = true;
            }
          }
        }
      }
    }
    else if (lookForXPF && ntohs(drh->d_type) == g_xpfRRCode && ntohs(drh->d_class) == QClass::IN && drh->d_ttl == 0) {
      if ((questionLen - pos) < ntohs(drh->d_clen)) {
        return;
      }

      foundXPF = parseXPFPayload(reinterpret_cast<const char*>(&question.at(pos)), ntohs(drh->d_clen), *xpfSource, xpfDest);
    }

    pos += ntohs(drh->d_clen);
  }
}

static void handleRunningTCPQuestion(int fd, FDMultiplexer::funcparam_t& var)
{
  shared_ptr<TCPConnection> conn=any_cast<shared_ptr<TCPConnection> >(var);

  if(conn->state==TCPConnection::BYTE0) {
    ssize_t bytes=recv(conn->getFD(), &conn->data[0], 2, 0);
    if(bytes==1)
      conn->state=TCPConnection::BYTE1;
    if(bytes==2) {
      conn->qlen=(((unsigned char)conn->data[0]) << 8)+ (unsigned char)conn->data[1];
      conn->data.resize(conn->qlen);
      conn->bytesread=0;
      conn->state=TCPConnection::GETQUESTION;
    }
    if(!bytes || bytes < 0) {
      t_fdm->removeReadFD(fd);
      return;
    }
  }
  else if(conn->state==TCPConnection::BYTE1) {
    ssize_t bytes=recv(conn->getFD(), &conn->data[1], 1, 0);
    if(bytes==1) {
      conn->state=TCPConnection::GETQUESTION;
      conn->qlen=(((unsigned char)conn->data[0]) << 8)+ (unsigned char)conn->data[1];
      conn->data.resize(conn->qlen);
      conn->bytesread=0;
    }
    if(!bytes || bytes < 0) {
      if(g_logCommonErrors)
        g_log<<Logger::Error<<"TCP client "<< conn->d_remote.toStringWithPort() <<" disconnected after first byte"<<endl;
      t_fdm->removeReadFD(fd);
      return;
    }
  }
  else if(conn->state==TCPConnection::GETQUESTION) {
    ssize_t bytes=recv(conn->getFD(), &conn->data[conn->bytesread], conn->qlen - conn->bytesread, 0);
    if(!bytes || bytes < 0 || bytes > std::numeric_limits<std::uint16_t>::max()) {
      if(g_logCommonErrors) {
        g_log<<Logger::Error<<"TCP client "<< conn->d_remote.toStringWithPort() <<" disconnected while reading question body"<<endl;
      }
      t_fdm->removeReadFD(fd);
      return;
    }
    conn->bytesread+=(uint16_t)bytes;
    if(conn->bytesread==conn->qlen) {
      conn->state = TCPConnection::BYTE0;
      std::unique_ptr<DNSComboWriter> dc;
      try {
        dc=std::unique_ptr<DNSComboWriter>(new DNSComboWriter(conn->data, g_now));
      }
      catch(const MOADNSException &mde) {
        g_stats.clientParseError++;
        if(g_logCommonErrors)
          g_log<<Logger::Error<<"Unable to parse packet from TCP client "<< conn->d_remote.toStringWithPort() <<endl;
        return;
      }
      dc->d_tcpConnection = conn; // carry the torch
      dc->setSocket(conn->getFD()); // this is the only time a copy is made of the actual fd
      dc->d_tcp=true;
      dc->setRemote(conn->d_remote);
      dc->setSource(conn->d_remote);
      ComboAddress dest;
      dest.reset();
      dest.sin4.sin_family = conn->d_remote.sin4.sin_family;
      socklen_t len = dest.getSocklen();
      getsockname(conn->getFD(), (sockaddr*)&dest, &len); // if this fails, we're ok with it
      dc->setLocal(dest);
      dc->setDestination(dest);
      DNSName qname;
      uint16_t qtype=0;
      uint16_t qclass=0;
      bool needECS = false;
      bool needXPF = g_XPFAcl.match(conn->d_remote);
      string requestorId;
      string deviceId;
      string deviceName;
      bool logQuery = false;
#ifdef HAVE_PROTOBUF
      auto luaconfsLocal = g_luaconfs.getLocal();
      if (checkProtobufExport(luaconfsLocal)) {
        needECS = true;
      }
      logQuery = t_protobufServers && luaconfsLocal->protobufExportConfig.logQueries;
      dc->d_logResponse = t_protobufServers && luaconfsLocal->protobufExportConfig.logResponses;
#endif /* HAVE_PROTOBUF */

#ifdef HAVE_FSTRM
      checkFrameStreamExport(luaconfsLocal);
#endif

      if(needECS || needXPF || (t_pdl && (t_pdl->d_gettag_ffi || t_pdl->d_gettag))) {

        try {
          EDNSOptionViewMap ednsOptions;
          bool xpfFound = false;
          dc->d_ecsParsed = true;
          dc->d_ecsFound = false;
          getQNameAndSubnet(conn->data, &qname, &qtype, &qclass,
                            dc->d_ecsFound, &dc->d_ednssubnet, g_gettagNeedsEDNSOptions ? &ednsOptions : nullptr,
                            xpfFound, needXPF ? &dc->d_source : nullptr, needXPF ? &dc->d_destination : nullptr);

          if(t_pdl) {
            try {
              if (t_pdl->d_gettag_ffi) {
                dc->d_tag = t_pdl->gettag_ffi(dc->d_source, dc->d_ednssubnet.source, dc->d_destination, qname, qtype, &dc->d_policyTags, dc->d_records, dc->d_data, ednsOptions, true, requestorId, deviceId, deviceName, dc->d_rcode, dc->d_ttlCap, dc->d_variable, logQuery, dc->d_logResponse, dc->d_followCNAMERecords);
              }
              else if (t_pdl->d_gettag) {
                dc->d_tag = t_pdl->gettag(dc->d_source, dc->d_ednssubnet.source, dc->d_destination, qname, qtype, &dc->d_policyTags, dc->d_data, ednsOptions, true, requestorId, deviceId, deviceName);
              }
            }
            catch(const std::exception& e)  {
              if(g_logCommonErrors)
                g_log<<Logger::Warning<<"Error parsing a query packet qname='"<<qname<<"' for tag determination, setting tag=0: "<<e.what()<<endl;
            }
          }
        }
        catch(const std::exception& e)
        {
          if(g_logCommonErrors)
            g_log<<Logger::Warning<<"Error parsing a query packet for tag determination, setting tag=0: "<<e.what()<<endl;
        }
      }

      const struct dnsheader* dh = reinterpret_cast<const struct dnsheader*>(&conn->data[0]);

#ifdef HAVE_PROTOBUF
      if(t_protobufServers || t_outgoingProtobufServers) {
        dc->d_requestorId = requestorId;
        dc->d_deviceId = deviceId;
        dc->d_deviceName = deviceName;
        dc->d_uuid = getUniqueID();
      }

      if(t_protobufServers) {
        try {

          if (logQuery && !(luaconfsLocal->protobufExportConfig.taggedOnly && dc->d_policyTags.empty())) {
            protobufLogQuery(luaconfsLocal->protobufMaskV4, luaconfsLocal->protobufMaskV6, dc->d_uuid, dc->d_source, dc->d_destination, dc->d_ednssubnet.source, true, dh->id, conn->qlen, qname, qtype, qclass, dc->d_policyTags, dc->d_requestorId, dc->d_deviceId, dc->d_deviceName);
          }
        }
        catch(std::exception& e) {
          if(g_logCommonErrors)
            g_log<<Logger::Warning<<"Error parsing a TCP query packet for edns subnet: "<<e.what()<<endl;
        }
      }
#endif
      if(t_pdl) {
        if(t_pdl->ipfilter(dc->d_source, dc->d_destination, *dh)) {
          if(!g_quiet)
            g_log<<Logger::Notice<<t_id<<" ["<<MT->getTid()<<"/"<<MT->numProcesses()<<"] DROPPED TCP question from "<<dc->d_source.toStringWithPort()<<(dc->d_source != dc->d_remote ? " (via "+dc->d_remote.toStringWithPort()+")" : "")<<" based on policy"<<endl;
          g_stats.policyDrops++;
          return;
        }
      }

      if(dc->d_mdp.d_header.qr) {
        g_stats.ignoredCount++;
        if(g_logCommonErrors) {
          g_log<<Logger::Error<<"Ignoring answer from TCP client "<< dc->getRemote() <<" on server socket!"<<endl;
        }
        return;
      }
      if(dc->d_mdp.d_header.opcode) {
        g_stats.ignoredCount++;
        if(g_logCommonErrors) {
          g_log<<Logger::Error<<"Ignoring non-query opcode from TCP client "<< dc->getRemote() <<" on server socket!"<<endl;
        }
        return;
      }
      else if (dh->qdcount == 0) {
        g_stats.emptyQueriesCount++;
        if(g_logCommonErrors) {
          g_log<<Logger::Error<<"Ignoring empty (qdcount == 0) query from "<< dc->getRemote() <<" on server socket!"<<endl;
        }
        return;
      }
      else {
        ++g_stats.qcounter;
        ++g_stats.tcpqcounter;
        ++conn->d_requestsInFlight;
        if (conn->d_requestsInFlight >= TCPConnection::s_maxInFlight) {
          t_fdm->removeReadFD(fd); // should no longer awake ourselves when there is data to read
        } else {
          Utility::gettimeofday(&g_now, 0); // needed?
          struct timeval ttd = g_now;
          t_fdm->setReadTTD(fd, ttd, g_tcpTimeout);
        }
        MT->makeThread(startDoResolve, dc.release()); // deletes dc
        return;
      }
    }
  }
}

//! Handle new incoming TCP connection
static void handleNewTCPQuestion(int fd, FDMultiplexer::funcparam_t& )
{
  ComboAddress addr;
  socklen_t addrlen=sizeof(addr);
  int newsock=accept(fd, (struct sockaddr*)&addr, &addrlen);
  if(newsock>=0) {
    if(MT->numProcesses() > g_maxMThreads) {
      g_stats.overCapacityDrops++;
      try {
        closesocket(newsock);
      }
      catch(const PDNSException& e) {
        g_log<<Logger::Error<<"Error closing TCP socket after an over capacity drop: "<<e.reason<<endl;
      }
      return;
    }

    if(t_remotes)
      t_remotes->push_back(addr);
    if(t_allowFrom && !t_allowFrom->match(&addr)) {
      if(!g_quiet)
        g_log<<Logger::Error<<"["<<MT->getTid()<<"] dropping TCP query from "<<addr.toString()<<", address not matched by allow-from"<<endl;

      g_stats.unauthorizedTCP++;
      try {
        closesocket(newsock);
      }
      catch(const PDNSException& e) {
        g_log<<Logger::Error<<"Error closing TCP socket after an ACL drop: "<<e.reason<<endl;
      }
      return;
    }
    if(g_maxTCPPerClient && t_tcpClientCounts->count(addr) && (*t_tcpClientCounts)[addr] >= g_maxTCPPerClient) {
      g_stats.tcpClientOverflow++;
      try {
        closesocket(newsock); // don't call TCPConnection::closeAndCleanup here - did not enter it in the counts yet!
      }
      catch(const PDNSException& e) {
        g_log<<Logger::Error<<"Error closing TCP socket after an overflow drop: "<<e.reason<<endl;
      }
      return;
    }

    setNonBlocking(newsock);
    std::shared_ptr<TCPConnection> tc = std::make_shared<TCPConnection>(newsock, addr);
    tc->state=TCPConnection::BYTE0;

    struct timeval ttd;
    Utility::gettimeofday(&ttd, 0);
    ttd.tv_sec += g_tcpTimeout;

    t_fdm->addReadFD(tc->getFD(), handleRunningTCPQuestion, tc, &ttd);
  }
}

static string* doProcessUDPQuestion(const std::string& question, const ComboAddress& fromaddr, const ComboAddress& destaddr, struct timeval tv, int fd)
{
  gettimeofday(&g_now, 0);
  if (tv.tv_sec) {
    struct timeval diff = g_now - tv;
    double delta=(diff.tv_sec*1000 + diff.tv_usec/1000.0);

    if(delta > 1000.0) {
      g_stats.tooOldDrops++;
      return nullptr;
    }
  }

  ++g_stats.qcounter;
  if(fromaddr.sin4.sin_family==AF_INET6)
     g_stats.ipv6qcounter++;

  string response;
  const struct dnsheader* dh = (struct dnsheader*)question.c_str();
  unsigned int ctag=0;
  uint32_t qhash = 0;
  bool needECS = false;
  bool needXPF = g_XPFAcl.match(fromaddr);
  std::vector<std::string> policyTags;
  LuaContext::LuaObject data;
  ComboAddress source = fromaddr;
  ComboAddress destination = destaddr;
  string requestorId;
  string deviceId;
  string deviceName;
  bool logQuery = false;
  bool logResponse = false;
#ifdef HAVE_PROTOBUF
  boost::uuids::uuid uniqueId;
  auto luaconfsLocal = g_luaconfs.getLocal();
  if (checkProtobufExport(luaconfsLocal)) {
    uniqueId = getUniqueID();
    needECS = true;
  } else if (checkOutgoingProtobufExport(luaconfsLocal)) {
    uniqueId = getUniqueID();
  }
  logQuery = t_protobufServers && luaconfsLocal->protobufExportConfig.logQueries;
  logResponse = t_protobufServers && luaconfsLocal->protobufExportConfig.logResponses;
#endif
#ifdef HAVE_FSTRM
  checkFrameStreamExport(luaconfsLocal);
#endif
  EDNSSubnetOpts ednssubnet;
  bool ecsFound = false;
  bool ecsParsed = false;
  uint16_t ecsBegin = 0;
  uint16_t ecsEnd = 0;
  std::vector<DNSRecord> records;
  boost::optional<int> rcode = boost::none;
  uint32_t ttlCap = std::numeric_limits<uint32_t>::max();
  bool variable = false;
  bool followCNAMEs = false;
  try {
    DNSName qname;
    uint16_t qtype=0;
    uint16_t qclass=0;
    uint32_t age;
    bool qnameParsed=false;
#ifdef MALLOC_TRACE
    /*
    static uint64_t last=0;
    if(!last)
      g_mtracer->clearAllocators();
    cout<<g_mtracer->getAllocs()-last<<" "<<g_mtracer->getNumOut()<<" -- BEGIN TRACE"<<endl;
    last=g_mtracer->getAllocs();
    cout<<g_mtracer->topAllocatorsString()<<endl;
    g_mtracer->clearAllocators();
    */
#endif

    if(needECS || needXPF || (t_pdl && (t_pdl->d_gettag || t_pdl->d_gettag_ffi))) {
      try {
        EDNSOptionViewMap ednsOptions;
        bool xpfFound = false;

        ecsFound = false;

        getQNameAndSubnet(question, &qname, &qtype, &qclass,
                          ecsFound, &ednssubnet, g_gettagNeedsEDNSOptions ? &ednsOptions : nullptr,
                          xpfFound, needXPF ? &source : nullptr, needXPF ? &destination : nullptr);

        qnameParsed = true;
        ecsParsed = true;

        if(t_pdl) {
          try {
            if (t_pdl->d_gettag_ffi) {
              ctag = t_pdl->gettag_ffi(source, ednssubnet.source, destination, qname, qtype, &policyTags, records, data, ednsOptions, false, requestorId, deviceId, deviceName, rcode, ttlCap, variable, logQuery, logResponse, followCNAMEs);
            }
            else if (t_pdl->d_gettag) {
              ctag = t_pdl->gettag(source, ednssubnet.source, destination, qname, qtype, &policyTags, data, ednsOptions, false, requestorId, deviceId, deviceName);
            }
          }
          catch(const std::exception& e)  {
            if(g_logCommonErrors)
              g_log<<Logger::Warning<<"Error parsing a query packet qname='"<<qname<<"' for tag determination, setting tag=0: "<<e.what()<<endl;
          }
        }
      }
      catch(const std::exception& e)
      {
        if(g_logCommonErrors)
          g_log<<Logger::Warning<<"Error parsing a query packet for tag determination, setting tag=0: "<<e.what()<<endl;
      }
    }

    bool cacheHit = false;
    boost::optional<RecProtoBufMessage> pbMessage(boost::none);
#ifdef HAVE_PROTOBUF
    if (t_protobufServers) {
      pbMessage = RecProtoBufMessage(DNSProtoBufMessage::DNSProtoBufMessageType::Response);
      pbMessage->setServerIdentity(SyncRes::s_serverID);
      if (logQuery && !(luaconfsLocal->protobufExportConfig.taggedOnly && policyTags.empty())) {
        protobufLogQuery(luaconfsLocal->protobufMaskV4, luaconfsLocal->protobufMaskV6, uniqueId, source, destination, ednssubnet.source, false, dh->id, question.size(), qname, qtype, qclass, policyTags, requestorId, deviceId, deviceName);
      }
    }
#endif /* HAVE_PROTOBUF */

    /* It might seem like a good idea to skip the packet cache lookup if we know that the answer is not cacheable,
       but it means that the hash would not be computed. If some script decides at a later time to mark back the answer
       as cacheable we would cache it with a wrong tag, so better safe than sorry. */
    vState valState;
    if (qnameParsed) {
      cacheHit = (!SyncRes::s_nopacketcache && t_packetCache->getResponsePacket(ctag, question, qname, qtype, qclass, g_now.tv_sec, &response, &age, &valState, &qhash, &ecsBegin, &ecsEnd, pbMessage ? &(*pbMessage) : nullptr));
    }
    else {
      cacheHit = (!SyncRes::s_nopacketcache && t_packetCache->getResponsePacket(ctag, question, qname, &qtype, &qclass, g_now.tv_sec, &response, &age, &valState, &qhash, &ecsBegin, &ecsEnd, pbMessage ? &(*pbMessage) : nullptr));
    }

    if (cacheHit) {
      if(valState == Bogus) {
        if(t_bogusremotes)
          t_bogusremotes->push_back(source);
        if(t_bogusqueryring)
          t_bogusqueryring->push_back(make_pair(qname, qtype));
      }

#ifdef HAVE_PROTOBUF
      if(t_protobufServers && logResponse && !(luaconfsLocal->protobufExportConfig.taggedOnly && pbMessage->getAppliedPolicy().empty() && pbMessage->getPolicyTags().empty())) {
        Netmask requestorNM(source, source.sin4.sin_family == AF_INET ? luaconfsLocal->protobufMaskV4 : luaconfsLocal->protobufMaskV6);
        const ComboAddress& requestor = requestorNM.getMaskedNetwork();
        pbMessage->update(uniqueId, &requestor, &destination, false, dh->id);
        pbMessage->setEDNSSubnet(ednssubnet.source, ednssubnet.source.isIpv4() ? luaconfsLocal->protobufMaskV4 : luaconfsLocal->protobufMaskV6);
        if (g_useKernelTimestamp && tv.tv_sec) {
          pbMessage->setQueryTime(tv.tv_sec, tv.tv_usec);
        }
        else {
          pbMessage->setQueryTime(g_now.tv_sec, g_now.tv_usec);
        }
        pbMessage->setRequestorId(requestorId);
        pbMessage->setDeviceId(deviceId);
        pbMessage->setDeviceName(deviceName);
        protobufLogResponse(*pbMessage);
      }
#endif /* HAVE_PROTOBUF */
      if(!g_quiet)
        g_log<<Logger::Notice<<t_id<< " question answered from packet cache tag="<<ctag<<" from "<<source.toStringWithPort()<<(source != fromaddr ? " (via "+fromaddr.toStringWithPort()+")" : "")<<endl;

      g_stats.packetCacheHits++;
      SyncRes::s_queries++;
      ageDNSPacket(response, age);
      struct msghdr msgh;
      struct iovec iov;
      cmsgbuf_aligned cbuf;
      fillMSGHdr(&msgh, &iov, &cbuf, 0, (char*)response.c_str(), response.length(), const_cast<ComboAddress*>(&fromaddr));
      msgh.msg_control=NULL;

      if(g_fromtosockets.count(fd)) {
        addCMsgSrcAddr(&msgh, &cbuf, &destaddr, 0);
      }
      if(sendmsg(fd, &msgh, 0) < 0 && g_logCommonErrors) {
        int err = errno;
        g_log << Logger::Warning << "Sending UDP reply to client " << source.toStringWithPort()
              << (source != fromaddr ? " (via " + fromaddr.toStringWithPort() + ")" : "") << " failed with: "
              << strerror(err) << endl;
      }
      if(response.length() >= sizeof(struct dnsheader)) {
        struct dnsheader tmpdh;
        memcpy(&tmpdh, response.c_str(), sizeof(tmpdh));
        updateResponseStats(tmpdh.rcode, source, response.length(), 0, 0);
      }
      g_stats.avgLatencyUsec=(1-1.0/g_latencyStatSize)*g_stats.avgLatencyUsec + 0.0; // we assume 0 usec
      g_stats.avgLatencyOursUsec=(1-1.0/g_latencyStatSize)*g_stats.avgLatencyOursUsec + 0.0; // we assume 0 usec
      return 0;
    }
  }
  catch(std::exception& e) {
    g_log<<Logger::Error<<"Error processing or aging answer packet: "<<e.what()<<endl;
    return 0;
  }

  if(t_pdl) {
    if(t_pdl->ipfilter(source, destination, *dh)) {
      if(!g_quiet)
	g_log<<Logger::Notice<<t_id<<" ["<<MT->getTid()<<"/"<<MT->numProcesses()<<"] DROPPED question from "<<source.toStringWithPort()<<(source != fromaddr ? " (via "+fromaddr.toStringWithPort()+")" : "")<<" based on policy"<<endl;
      g_stats.policyDrops++;
      return 0;
    }
  }

  if(MT->numProcesses() > g_maxMThreads) {
    if(!g_quiet)
      g_log<<Logger::Notice<<t_id<<" ["<<MT->getTid()<<"/"<<MT->numProcesses()<<"] DROPPED question from "<<source.toStringWithPort()<<(source != fromaddr ? " (via "+fromaddr.toStringWithPort()+")" : "")<<", over capacity"<<endl;

    g_stats.overCapacityDrops++;
    return 0;
  }

  auto dc = std::unique_ptr<DNSComboWriter>(new DNSComboWriter(question, g_now, std::move(policyTags), std::move(data), std::move(records)));
  dc->setSocket(fd);
  dc->d_tag=ctag;
  dc->d_qhash=qhash;
  dc->setRemote(fromaddr);
  dc->setSource(source);
  dc->setLocal(destaddr);
  dc->setDestination(destination);
  dc->d_tcp=false;
  dc->d_ecsFound = ecsFound;
  dc->d_ecsParsed = ecsParsed;
  dc->d_ecsBegin = ecsBegin;
  dc->d_ecsEnd = ecsEnd;
  dc->d_ednssubnet = ednssubnet;
  dc->d_ttlCap = ttlCap;
  dc->d_variable = variable;
  dc->d_followCNAMERecords = followCNAMEs;
  dc->d_rcode = rcode;
  dc->d_logResponse = logResponse;
#ifdef HAVE_PROTOBUF
  if (t_protobufServers || t_outgoingProtobufServers) {
    dc->d_uuid = std::move(uniqueId);
  }
  dc->d_requestorId = requestorId;
  dc->d_deviceId = deviceId;
  dc->d_deviceName = deviceName;
  dc->d_kernelTimestamp = tv;
#endif

  MT->makeThread(startDoResolve, (void*) dc.release()); // deletes dc
  return 0;
}


static void handleNewUDPQuestion(int fd, FDMultiplexer::funcparam_t& var)
{
  ssize_t len;
  static const size_t maxIncomingQuerySize = 512;
  static thread_local std::string data;
  ComboAddress fromaddr;
  struct msghdr msgh;
  struct iovec iov;
  cmsgbuf_aligned cbuf;
  bool firstQuery = true;

  for(size_t queriesCounter = 0; queriesCounter < s_maxUDPQueriesPerRound; queriesCounter++) {
    data.resize(maxIncomingQuerySize);
    fromaddr.sin6.sin6_family=AF_INET6; // this makes sure fromaddr is big enough
    fillMSGHdr(&msgh, &iov, &cbuf, sizeof(cbuf), &data[0], data.size(), &fromaddr);

    if((len=recvmsg(fd, &msgh, 0)) >= 0) {

      firstQuery = false;

      if (static_cast<size_t>(len) < sizeof(dnsheader)) {
        g_stats.ignoredCount++;
        if (!g_quiet) {
          g_log<<Logger::Error<<"Ignoring too-short ("<<std::to_string(len)<<") query from "<<fromaddr.toString()<<endl;
        }
        return;
      }

      if (msgh.msg_flags & MSG_TRUNC) {
        g_stats.truncatedDrops++;
        if (!g_quiet) {
          g_log<<Logger::Error<<"Ignoring truncated query from "<<fromaddr.toString()<<endl;
        }
        return;
      }

      if(t_remotes) {
        t_remotes->push_back(fromaddr);
      }

      if(t_allowFrom && !t_allowFrom->match(&fromaddr)) {
        if(!g_quiet) {
          g_log<<Logger::Error<<"["<<MT->getTid()<<"] dropping UDP query from "<<fromaddr.toString()<<", address not matched by allow-from"<<endl;
        }

        g_stats.unauthorizedUDP++;
        return;
      }
      BOOST_STATIC_ASSERT(offsetof(sockaddr_in, sin_port) == offsetof(sockaddr_in6, sin6_port));
      if(!fromaddr.sin4.sin_port) { // also works for IPv6
        if(!g_quiet) {
          g_log<<Logger::Error<<"["<<MT->getTid()<<"] dropping UDP query from "<<fromaddr.toStringWithPort()<<", can't deal with port 0"<<endl;
        }

        g_stats.clientParseError++; // not quite the best place to put it, but needs to go somewhere
        return;
      }

      try {
        data.resize(static_cast<size_t>(len));
        dnsheader* dh=(dnsheader*)&data[0];

        if(dh->qr) {
          g_stats.ignoredCount++;
          if(g_logCommonErrors) {
            g_log<<Logger::Error<<"Ignoring answer from "<<fromaddr.toString()<<" on server socket!"<<endl;
          }
        }
        else if(dh->opcode) {
          g_stats.ignoredCount++;
          if(g_logCommonErrors) {
            g_log<<Logger::Error<<"Ignoring non-query opcode "<<dh->opcode<<" from "<<fromaddr.toString()<<" on server socket!"<<endl;
          }
        }
        else if (dh->qdcount == 0) {
          g_stats.emptyQueriesCount++;
          if(g_logCommonErrors) {
            g_log<<Logger::Error<<"Ignoring empty (qdcount == 0) query from "<<fromaddr.toString()<<" on server socket!"<<endl;
          }
        }
        else {
          struct timeval tv={0,0};
          HarvestTimestamp(&msgh, &tv);
          ComboAddress dest;
          dest.reset(); // this makes sure we ignore this address if not returned by recvmsg above
          auto loc = rplookup(g_listenSocketsAddresses, fd);
          if(HarvestDestinationAddress(&msgh, &dest)) {
            // but.. need to get port too
            if(loc) {
              dest.sin4.sin_port = loc->sin4.sin_port;
            }
          }
          else {
            if(loc) {
              dest = *loc;
            }
            else {
              dest.sin4.sin_family = fromaddr.sin4.sin_family;
              socklen_t slen = dest.getSocklen();
              getsockname(fd, (sockaddr*)&dest, &slen); // if this fails, we're ok with it
            }
          }

          if(g_weDistributeQueries) {
            distributeAsyncFunction(data, boost::bind(doProcessUDPQuestion, data, fromaddr, dest, tv, fd));
          }
          else {
            ++s_threadInfos[t_id].numberOfDistributedQueries;
            doProcessUDPQuestion(data, fromaddr, dest, tv, fd);
          }
        }
      }
      catch(const MOADNSException &mde) {
        g_stats.clientParseError++;
        if(g_logCommonErrors) {
          g_log<<Logger::Error<<"Unable to parse packet from remote UDP client "<<fromaddr.toString() <<": "<<mde.what()<<endl;
        }
      }
      catch(const std::runtime_error& e) {
        g_stats.clientParseError++;
        if(g_logCommonErrors) {
          g_log<<Logger::Error<<"Unable to parse packet from remote UDP client "<<fromaddr.toString() <<": "<<e.what()<<endl;
        }
      }
    }
    else {
      // cerr<<t_id<<" had error: "<<stringerror()<<endl;
      if(firstQuery && errno == EAGAIN) {
        g_stats.noPacketError++;
      }

      break;
    }
  }
}

static void makeTCPServerSockets(deferredAdd_t& deferredAdds, std::set<int>& tcpSockets)
{
  int fd;
  vector<string>locals;
  stringtok(locals,::arg()["local-address"]," ,");

  if(locals.empty())
    throw PDNSException("No local address specified");

  for(vector<string>::const_iterator i=locals.begin();i!=locals.end();++i) {
    ServiceTuple st;
    st.port=::arg().asNum("local-port");
    parseService(*i, st);

    ComboAddress sin;

    sin.reset();
    sin.sin4.sin_family = AF_INET;
    if(!IpToU32(st.host, (uint32_t*)&sin.sin4.sin_addr.s_addr)) {
      sin.sin6.sin6_family = AF_INET6;
      if(makeIPv6sockaddr(st.host, &sin.sin6) < 0)
        throw PDNSException("Unable to resolve local address for TCP server on '"+ st.host +"'");
    }

    fd=socket(sin.sin6.sin6_family, SOCK_STREAM, 0);
    if(fd<0)
      throw PDNSException("Making a TCP server socket for resolver: "+stringerror());

    setCloseOnExec(fd);

    int tmp=1;
    if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof tmp)<0) {
      g_log<<Logger::Error<<"Setsockopt failed for TCP listening socket"<<endl;
      exit(1);
    }
    if(sin.sin6.sin6_family == AF_INET6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &tmp, sizeof(tmp)) < 0) {
      int err = errno;
      g_log<<Logger::Error<<"Failed to set IPv6 socket to IPv6 only, continuing anyhow: "<<strerror(err)<<endl;
    }

#ifdef TCP_DEFER_ACCEPT
    if(setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &tmp, sizeof tmp) >= 0) {
      if(i==locals.begin())
        g_log<<Logger::Info<<"Enabled TCP data-ready filter for (slight) DoS protection"<<endl;
    }
#endif

    if( ::arg().mustDo("non-local-bind") )
	Utility::setBindAny(AF_INET, fd);

#ifdef SO_REUSEPORT
    if(g_reusePort) {
      if(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &tmp, sizeof(tmp)) < 0)
        throw PDNSException("SO_REUSEPORT: "+stringerror());
    }
#endif

    if (::arg().asNum("tcp-fast-open") > 0) {
#ifdef TCP_FASTOPEN
      int fastOpenQueueSize = ::arg().asNum("tcp-fast-open");
      if (setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &fastOpenQueueSize, sizeof fastOpenQueueSize) < 0) {
        int err = errno;
        g_log<<Logger::Error<<"Failed to enable TCP Fast Open for listening socket: "<<strerror(err)<<endl;
      }
#else
      g_log<<Logger::Warning<<"TCP Fast Open configured but not supported for listening socket"<<endl;
#endif
    }

    sin.sin4.sin_port = htons(st.port);
    socklen_t socklen=sin.sin4.sin_family==AF_INET ? sizeof(sin.sin4) : sizeof(sin.sin6);
    if (::bind(fd, (struct sockaddr *)&sin, socklen )<0)
      throw PDNSException("Binding TCP server socket for "+ st.host +": "+stringerror());

    setNonBlocking(fd);
    setSocketSendBuffer(fd, 65000);
    listen(fd, 128);
    deferredAdds.push_back(make_pair(fd, handleNewTCPQuestion));
    tcpSockets.insert(fd);

    // we don't need to update g_listenSocketsAddresses since it doesn't work for TCP/IP:
    //  - fd is not that which we know here, but returned from accept()
    if(sin.sin4.sin_family == AF_INET)
      g_log<<Logger::Info<<"Listening for TCP queries on "<< sin.toString() <<":"<<st.port<<endl;
    else
      g_log<<Logger::Info<<"Listening for TCP queries on ["<< sin.toString() <<"]:"<<st.port<<endl;
  }
}

static void makeUDPServerSockets(deferredAdd_t& deferredAdds)
{
  int one=1;
  vector<string>locals;
  stringtok(locals,::arg()["local-address"]," ,");

  if(locals.empty())
    throw PDNSException("No local address specified");

  for(vector<string>::const_iterator i=locals.begin();i!=locals.end();++i) {
    ServiceTuple st;
    st.port=::arg().asNum("local-port");
    parseService(*i, st);

    ComboAddress sin;

    sin.reset();
    sin.sin4.sin_family = AF_INET;
    if(!IpToU32(st.host.c_str() , (uint32_t*)&sin.sin4.sin_addr.s_addr)) {
      sin.sin6.sin6_family = AF_INET6;
      if(makeIPv6sockaddr(st.host, &sin.sin6) < 0)
        throw PDNSException("Unable to resolve local address for UDP server on '"+ st.host +"'");
    }

    int fd=socket(sin.sin4.sin_family, SOCK_DGRAM, 0);
    if(fd < 0) {
      throw PDNSException("Making a UDP server socket for resolver: "+stringerror());
    }
    if (!setSocketTimestamps(fd))
      g_log<<Logger::Warning<<"Unable to enable timestamp reporting for socket"<<endl;

    if(IsAnyAddress(sin)) {
      if(sin.sin4.sin_family == AF_INET)
        if(!setsockopt(fd, IPPROTO_IP, GEN_IP_PKTINFO, &one, sizeof(one)))     // linux supports this, so why not - might fail on other systems
          g_fromtosockets.insert(fd);
#ifdef IPV6_RECVPKTINFO
      if(sin.sin4.sin_family == AF_INET6)
        if(!setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one)))
          g_fromtosockets.insert(fd);
#endif
      if(sin.sin6.sin6_family == AF_INET6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) < 0) {
        int err = errno;
	      g_log<<Logger::Error<<"Failed to set IPv6 socket to IPv6 only, continuing anyhow: "<<strerror(err)<<endl;
      }
    }
    if( ::arg().mustDo("non-local-bind") )
	Utility::setBindAny(AF_INET6, fd);

    setCloseOnExec(fd);

    setSocketReceiveBuffer(fd, 250000);
    sin.sin4.sin_port = htons(st.port);

  
#ifdef SO_REUSEPORT
    if(g_reusePort) {
      if(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0)
        throw PDNSException("SO_REUSEPORT: "+stringerror());
    }
#endif

    if (sin.isIPv4()) {
      try {
        setSocketIgnorePMTU(fd);
      }
      catch(const std::exception& e) {
        g_log<<Logger::Warning<<"Failed to set IP_MTU_DISCOVER on UDP server socket: "<<e.what()<<endl;
      }
    }

    socklen_t socklen=sin.getSocklen();
    if (::bind(fd, (struct sockaddr *)&sin, socklen)<0)
      throw PDNSException("Resolver binding to server socket on port "+ std::to_string(st.port) +" for "+ st.host+": "+stringerror());

    setNonBlocking(fd);

    deferredAdds.push_back(make_pair(fd, handleNewUDPQuestion));
    g_listenSocketsAddresses[fd]=sin;  // this is written to only from the startup thread, not from the workers
    if(sin.sin4.sin_family == AF_INET)
      g_log<<Logger::Info<<"Listening for UDP queries on "<< sin.toString() <<":"<<st.port<<endl;
    else
      g_log<<Logger::Info<<"Listening for UDP queries on ["<< sin.toString() <<"]:"<<st.port<<endl;
  }
}

static void daemonize(void)
{
  if(fork())
    exit(0); // bye bye

  setsid();

  int i=open("/dev/null",O_RDWR); /* open stdin */
  if(i < 0)
    g_log<<Logger::Critical<<"Unable to open /dev/null: "<<stringerror()<<endl;
  else {
    dup2(i,0); /* stdin */
    dup2(i,1); /* stderr */
    dup2(i,2); /* stderr */
    close(i);
  }
}

static void termIntHandler(int)
{
  doExit();
}

static void usr1Handler(int)
{
  statsWanted=true;
}

static void usr2Handler(int)
{
  g_quiet= !g_quiet;
  SyncRes::setDefaultLogMode(g_quiet ? SyncRes::LogNone : SyncRes::Log);
  ::arg().set("quiet")=g_quiet ? "" : "no";
}

static void doStats(void)
{
  static time_t lastOutputTime;
  static uint64_t lastQueryCount;

  uint64_t cacheHits = broadcastAccFunction<uint64_t>(pleaseGetCacheHits);
  uint64_t cacheMisses = broadcastAccFunction<uint64_t>(pleaseGetCacheMisses);

  if(g_stats.qcounter && (cacheHits + cacheMisses) && SyncRes::s_queries && SyncRes::s_outqueries) {
    g_log<<Logger::Notice<<"stats: "<<g_stats.qcounter<<" questions, "<<
      broadcastAccFunction<uint64_t>(pleaseGetCacheSize)<< " cache entries, "<<
      broadcastAccFunction<uint64_t>(pleaseGetNegCacheSize)<<" negative entries, "<<
      (int)((cacheHits*100.0)/(cacheHits+cacheMisses))<<"% cache hits"<<endl;

    g_log<<Logger::Notice<<"stats: throttle map: "
      << broadcastAccFunction<uint64_t>(pleaseGetThrottleSize) <<", ns speeds: "
      << broadcastAccFunction<uint64_t>(pleaseGetNsSpeedsSize)<<endl;
    g_log<<Logger::Notice<<"stats: outpacket/query ratio "<<(int)(SyncRes::s_outqueries*100.0/SyncRes::s_queries)<<"%";
    g_log<<Logger::Notice<<", "<<(int)(SyncRes::s_throttledqueries*100.0/(SyncRes::s_outqueries+SyncRes::s_throttledqueries))<<"% throttled, "
     <<SyncRes::s_nodelegated<<" no-delegation drops"<<endl;
    g_log<<Logger::Notice<<"stats: "<<SyncRes::s_tcpoutqueries<<" outgoing tcp connections, "<<
      broadcastAccFunction<uint64_t>(pleaseGetConcurrentQueries)<<" queries running, "<<SyncRes::s_outgoingtimeouts<<" outgoing timeouts"<<endl;

    //g_log<<Logger::Notice<<"stats: "<<g_stats.ednsPingMatches<<" ping matches, "<<g_stats.ednsPingMismatches<<" mismatches, "<<
      //g_stats.noPingOutQueries<<" outqueries w/o ping, "<< g_stats.noEdnsOutQueries<<" w/o EDNS"<<endl;

    g_log<<Logger::Notice<<"stats: " <<  broadcastAccFunction<uint64_t>(pleaseGetPacketCacheSize) <<
    " packet cache entries, "<<(int)(100.0*broadcastAccFunction<uint64_t>(pleaseGetPacketCacheHits)/SyncRes::s_queries) << "% packet cache hits"<<endl;

    size_t idx = 0;
    for (const auto& threadInfo : s_threadInfos) {
      if(threadInfo.isWorker) {
        g_log<<Logger::Notice<<"stats: thread "<<idx<<" has been distributed "<<threadInfo.numberOfDistributedQueries<<" queries"<<endl;
        ++idx;
      }
    }

    time_t now = time(0);
    if(lastOutputTime && lastQueryCount && now != lastOutputTime) {
      g_log<<Logger::Notice<<"stats: "<< (SyncRes::s_queries - lastQueryCount) / (now - lastOutputTime) <<" qps (average over "<< (now - lastOutputTime) << " seconds)"<<endl;
    }
    lastOutputTime = now;
    lastQueryCount = SyncRes::s_queries;
  }
  else if(statsWanted)
    g_log<<Logger::Notice<<"stats: no stats yet!"<<endl;

  statsWanted=false;
}

static void houseKeeping(void *)
{
  static thread_local time_t last_rootupdate, last_prune, last_secpoll, last_trustAnchorUpdate{0};
  static thread_local int cleanCounter=0;
  static thread_local bool s_running;  // houseKeeping can get suspended in secpoll, and be restarted, which makes us do duplicate work
  auto luaconfsLocal = g_luaconfs.getLocal();

  if (last_trustAnchorUpdate == 0 && !luaconfsLocal->trustAnchorFileInfo.fname.empty() && luaconfsLocal->trustAnchorFileInfo.interval != 0) {
    // Loading the Lua config file already "refreshed" the TAs
    last_trustAnchorUpdate = g_now.tv_sec + luaconfsLocal->trustAnchorFileInfo.interval * 3600;
  }

  try {
    if(s_running) {
      return;
    }
    s_running=true;

    struct timeval now;
    Utility::gettimeofday(&now, 0);

    if(now.tv_sec - last_prune > (time_t)(5 + t_id)) {
      t_RC->doPrune(g_maxCacheEntries / g_numThreads); // this function is local to a thread, so fine anyhow
      t_packetCache->doPruneTo(g_maxPacketCacheEntries / g_numWorkerThreads);

      SyncRes::pruneNegCache(g_maxCacheEntries / (g_numWorkerThreads * 10));

      if(!((cleanCounter++)%40)) {  // this is a full scan!
	time_t limit=now.tv_sec-300;
        SyncRes::pruneNSSpeeds(limit);
      }
      last_prune=time(0);
    }

    if(now.tv_sec - last_rootupdate > 7200) {
      int res = SyncRes::getRootNS(g_now, nullptr);
      if (!res) {
        last_rootupdate=now.tv_sec;
        primeRootNSZones(g_dnssecmode != DNSSECMode::Off);
      }
    }

    if(isHandlerThread()) {

      if(now.tv_sec - last_secpoll >= 3600) {
	try {
	  doSecPoll(&last_secpoll);
	}
	catch(std::exception& e)
        {
          g_log<<Logger::Error<<"Exception while performing security poll: "<<e.what()<<endl;
        }
        catch(PDNSException& e)
        {
          g_log<<Logger::Error<<"Exception while performing security poll: "<<e.reason<<endl;
        }
        catch(ImmediateServFailException &e)
        {
          g_log<<Logger::Error<<"Exception while performing security poll: "<<e.reason<<endl;
        }
        catch(...)
        {
          g_log<<Logger::Error<<"Exception while performing security poll"<<endl;
        }
      }

      if (!luaconfsLocal->trustAnchorFileInfo.fname.empty() && luaconfsLocal->trustAnchorFileInfo.interval != 0 &&
          g_now.tv_sec - last_trustAnchorUpdate >= (luaconfsLocal->trustAnchorFileInfo.interval * 3600)) {
        g_log<<Logger::Debug<<"Refreshing Trust Anchors from file"<<endl;
        try {
          map<DNSName, dsmap_t> dsAnchors;
          if (updateTrustAnchorsFromFile(luaconfsLocal->trustAnchorFileInfo.fname, dsAnchors)) {
            g_luaconfs.modify([&dsAnchors](LuaConfigItems& lci) {
                lci.dsAnchors = dsAnchors;
            });
          }
          last_trustAnchorUpdate = now.tv_sec;
        } catch (const PDNSException &pe) {
          g_log<<Logger::Error<<"Unable to update Trust Anchors: "<<pe.reason<<endl;
        }
      }
    }
    s_running=false;
  }
  catch(PDNSException& ae)
    {
      s_running=false;
      g_log<<Logger::Error<<"Fatal error in housekeeping thread: "<<ae.reason<<endl;
      throw;
    }
}

static void makeThreadPipes()
{
  auto pipeBufferSize = ::arg().asNum("distribution-pipe-buffer-size");
  if (pipeBufferSize > 0) {
    g_log<<Logger::Info<<"Resizing the buffer of the distribution pipe to "<<pipeBufferSize<<endl;
  }

  /* thread 0 is the handler / SNMP, we start at 1 */
  for(unsigned int n = 1; n <= (g_numWorkerThreads + g_numDistributorThreads); ++n) {
    auto& threadInfos = s_threadInfos.at(n);

    int fd[2];
    if(pipe(fd) < 0)
      unixDie("Creating pipe for inter-thread communications");

    threadInfos.pipes.readToThread = fd[0];
    threadInfos.pipes.writeToThread = fd[1];

    if(pipe(fd) < 0)
      unixDie("Creating pipe for inter-thread communications");

    threadInfos.pipes.readFromThread = fd[0];
    threadInfos.pipes.writeFromThread = fd[1];

    if(pipe(fd) < 0)
      unixDie("Creating pipe for inter-thread communications");

    threadInfos.pipes.readQueriesToThread = fd[0];
    threadInfos.pipes.writeQueriesToThread = fd[1];

    if (pipeBufferSize > 0) {
      if (!setPipeBufferSize(threadInfos.pipes.writeQueriesToThread, pipeBufferSize)) {
        int err = errno;
        g_log<<Logger::Warning<<"Error resizing the buffer of the distribution pipe for thread "<<n<<" to "<<pipeBufferSize<<": "<<strerror(err)<<endl;
        auto existingSize = getPipeBufferSize(threadInfos.pipes.writeQueriesToThread);
        if (existingSize > 0) {
          g_log<<Logger::Warning<<"The current size of the distribution pipe's buffer for thread "<<n<<" is "<<existingSize<<endl;
        }
      }
    }

    if (!setNonBlocking(threadInfos.pipes.writeQueriesToThread)) {
      unixDie("Making pipe for inter-thread communications non-blocking");
    }
  }
}

struct ThreadMSG
{
  pipefunc_t func;
  bool wantAnswer;
};

void broadcastFunction(const pipefunc_t& func)
{
  /* This function might be called by the worker with t_id 0 during startup
     for the initialization of ACLs and domain maps. After that it should only
     be called by the handler. */

  if (s_threadInfos.empty() && isHandlerThread()) {
    /* the handler and  distributors will call themselves below, but
       during startup we get called while s_threadInfos has not been
       populated yet to update the ACL or domain maps, so we need to
       handle that case.
    */
    func();
  }

  unsigned int n = 0;
  for (const auto& threadInfo : s_threadInfos) {
    if(n++ == t_id) {
      func(); // don't write to ourselves!
      continue;
    }

    ThreadMSG* tmsg = new ThreadMSG();
    tmsg->func = func;
    tmsg->wantAnswer = true;
    if(write(threadInfo.pipes.writeToThread, &tmsg, sizeof(tmsg)) != sizeof(tmsg)) {
      delete tmsg;

      unixDie("write to thread pipe returned wrong size or error");
    }

    string* resp = nullptr;
    if(read(threadInfo.pipes.readFromThread, &resp, sizeof(resp)) != sizeof(resp))
      unixDie("read from thread pipe returned wrong size or error");

    if(resp) {
      delete resp;
      resp = nullptr;
    }
  }
}

static bool trySendingQueryToWorker(unsigned int target, ThreadMSG* tmsg)
{
  auto& targetInfo = s_threadInfos[target];
  if(!targetInfo.isWorker) {
    g_log<<Logger::Error<<"distributeAsyncFunction() tried to assign a query to a non-worker thread"<<endl;
    exit(1);
  }

  const auto& tps = targetInfo.pipes;

  ssize_t written = write(tps.writeQueriesToThread, &tmsg, sizeof(tmsg));
  if (written > 0) {
    if (static_cast<size_t>(written) != sizeof(tmsg)) {
      delete tmsg;
      unixDie("write to thread pipe returned wrong size or error");
    }
  }
  else {
    int error = errno;
    if (error == EAGAIN || error == EWOULDBLOCK) {
      return false;
    } else {
      delete tmsg;
      unixDie("write to thread pipe returned wrong size or error:" + std::to_string(error));
    }
  }

  ++targetInfo.numberOfDistributedQueries;

  return true;
}

static unsigned int getWorkerLoad(size_t workerIdx)
{
  const auto mt = s_threadInfos[/* skip handler */ 1 + g_numDistributorThreads + workerIdx].mt;
  if (mt != nullptr) {
    return mt->numProcesses();
  }
  return 0;
}

static unsigned int selectWorker(unsigned int hash)
{
  if (s_balancingFactor == 0) {
    return /* skip handler */ 1 + g_numDistributorThreads + (hash % g_numWorkerThreads);
  }

  /* we start with one, representing the query we are currently handling */
  double currentLoad = 1;
  std::vector<unsigned int> load(g_numWorkerThreads);
  for (size_t idx = 0; idx < g_numWorkerThreads; idx++) {
    load[idx] = getWorkerLoad(idx);
    currentLoad += load[idx];
    // cerr<<"load for worker "<<idx<<" is "<<load[idx]<<endl;
  }

  double targetLoad = (currentLoad / g_numWorkerThreads) * s_balancingFactor;
  // cerr<<"total load is "<<currentLoad<<", number of workers is "<<g_numWorkerThreads<<", target load is "<<targetLoad<<endl;

  unsigned int worker = hash % g_numWorkerThreads;
  /* at least one server has to be at or below the average load */
  if (load[worker] > targetLoad) {
    ++g_stats.rebalancedQueries;
    do {
      // cerr<<"worker "<<worker<<" is above the target load, selecting another one"<<endl;
      worker = (worker + 1) % g_numWorkerThreads;
    }
    while(load[worker] > targetLoad);
  }

  return /* skip handler */ 1 + g_numDistributorThreads + worker;
}

// This function is only called by the distributor threads, when pdns-distributes-queries is set
void distributeAsyncFunction(const string& packet, const pipefunc_t& func)
{
  if (!isDistributorThread()) {
    g_log<<Logger::Error<<"distributeAsyncFunction() has been called by a worker ("<<t_id<<")"<<endl;
    exit(1);
  }

  unsigned int hash = hashQuestion(packet.c_str(), packet.length(), g_disthashseed);
  unsigned int target = selectWorker(hash);

  ThreadMSG* tmsg = new ThreadMSG();
  tmsg->func = func;
  tmsg->wantAnswer = false;

  if (!trySendingQueryToWorker(target, tmsg)) {
    /* if this function failed but did not raise an exception, it means that the pipe
       was full, let's try another one */
    unsigned int newTarget = 0;
    do {
      newTarget = /* skip handler */ 1 + g_numDistributorThreads + dns_random(g_numWorkerThreads);
    } while (newTarget == target);

    if (!trySendingQueryToWorker(newTarget, tmsg)) {
      g_stats.queryPipeFullDrops++;
      delete tmsg;
    }
  }
}

static void handlePipeRequest(int fd, FDMultiplexer::funcparam_t& var)
{
  ThreadMSG* tmsg = nullptr;

  if(read(fd, &tmsg, sizeof(tmsg)) != sizeof(tmsg)) { // fd == readToThread || fd == readQueriesToThread
    unixDie("read from thread pipe returned wrong size or error");
  }

  void *resp=0;
  try {
    resp = tmsg->func();
  }
  catch(std::exception& e) {
    if(g_logCommonErrors)
      g_log<<Logger::Error<<"PIPE function we executed created exception: "<<e.what()<<endl; // but what if they wanted an answer.. we send 0
  }
  catch(PDNSException& e) {
    if(g_logCommonErrors)
      g_log<<Logger::Error<<"PIPE function we executed created PDNS exception: "<<e.reason<<endl; // but what if they wanted an answer.. we send 0
  }
  if(tmsg->wantAnswer) {
    const auto& threadInfo = s_threadInfos.at(t_id);
    if(write(threadInfo.pipes.writeFromThread, &resp, sizeof(resp)) != sizeof(resp)) {
      delete tmsg;
      unixDie("write to thread pipe returned wrong size or error");
    }
  }

  delete tmsg;
}

template<class T> void *voider(const boost::function<T*()>& func)
{
  return func();
}

vector<ComboAddress>& operator+=(vector<ComboAddress>&a, const vector<ComboAddress>& b)
{
  a.insert(a.end(), b.begin(), b.end());
  return a;
}

vector<pair<string, uint16_t> >& operator+=(vector<pair<string, uint16_t> >&a, const vector<pair<string, uint16_t> >& b)
{
  a.insert(a.end(), b.begin(), b.end());
  return a;
}

vector<pair<DNSName, uint16_t> >& operator+=(vector<pair<DNSName, uint16_t> >&a, const vector<pair<DNSName, uint16_t> >& b)
{
  a.insert(a.end(), b.begin(), b.end());
  return a;
}


/*
  This function should only be called by the handler to gather metrics, wipe the cache,
  reload the Lua script (not the Lua config) or change the current trace regex,
  and by the SNMP thread to gather metrics. */
template<class T> T broadcastAccFunction(const boost::function<T*()>& func)
{
  if (!isHandlerThread()) {
    g_log<<Logger::Error<<"broadcastAccFunction has been called by a worker ("<<t_id<<")"<<endl;
    exit(1);
  }

  unsigned int n = 0;
  T ret=T();
  for (const auto& threadInfo : s_threadInfos) {
    if (n++ == t_id) {
      continue;
    }

    const auto& tps = threadInfo.pipes;
    ThreadMSG* tmsg = new ThreadMSG();
    tmsg->func = boost::bind(voider<T>, func);
    tmsg->wantAnswer = true;

    if(write(tps.writeToThread, &tmsg, sizeof(tmsg)) != sizeof(tmsg)) {
      delete tmsg;
      unixDie("write to thread pipe returned wrong size or error");
    }

    T* resp = nullptr;
    if(read(tps.readFromThread, &resp, sizeof(resp)) != sizeof(resp))
      unixDie("read from thread pipe returned wrong size or error");

    if(resp) {
      ret += *resp;
      delete resp;
      resp = nullptr;
    }
  }
  return ret;
}

template string broadcastAccFunction(const boost::function<string*()>& fun); // explicit instantiation
template uint64_t broadcastAccFunction(const boost::function<uint64_t*()>& fun); // explicit instantiation
template vector<ComboAddress> broadcastAccFunction(const boost::function<vector<ComboAddress> *()>& fun); // explicit instantiation
template vector<pair<DNSName,uint16_t> > broadcastAccFunction(const boost::function<vector<pair<DNSName, uint16_t> > *()>& fun); // explicit instantiation
template ThreadTimes broadcastAccFunction(const boost::function<ThreadTimes*()>& fun);

static void handleRCC(int fd, FDMultiplexer::funcparam_t& var)
{
  try {
    string remote;
    string msg=s_rcc.recv(&remote);
    RecursorControlParser rcp;
    RecursorControlParser::func_t* command;

    string answer=rcp.getAnswer(msg, &command);

    // If we are inside a chroot, we need to strip
    if (!arg()["chroot"].empty()) {
      size_t len = arg()["chroot"].length();
      remote = remote.substr(len);
    }

    s_rcc.send(answer, &remote);
    command();
  }
  catch(const std::exception& e) {
    g_log<<Logger::Error<<"Error dealing with control socket request: "<<e.what()<<endl;
  }
  catch(const PDNSException& ae) {
    g_log<<Logger::Error<<"Error dealing with control socket request: "<<ae.reason<<endl;
  }
}

static void handleTCPClientReadable(int fd, FDMultiplexer::funcparam_t& var)
{
  PacketID* pident=any_cast<PacketID>(&var);
  //  cerr<<"handleTCPClientReadable called for fd "<<fd<<", pident->inNeeded: "<<pident->inNeeded<<", "<<pident->sock->getHandle()<<endl;

  shared_array<char> buffer(new char[pident->inNeeded]);

  ssize_t ret=recv(fd, buffer.get(), pident->inNeeded,0);
  if(ret > 0) {
    pident->inMSG.append(&buffer[0], &buffer[ret]);
    pident->inNeeded-=(size_t)ret;
    if(!pident->inNeeded || pident->inIncompleteOkay) {
      //      cerr<<"Got entire load of "<<pident->inMSG.size()<<" bytes"<<endl;
      PacketID pid=*pident;
      string msg=pident->inMSG;

      t_fdm->removeReadFD(fd);
      MT->sendEvent(pid, &msg);
    }
    else {
      //      cerr<<"Still have "<<pident->inNeeded<<" left to go"<<endl;
    }
  }
  else {
    PacketID tmp=*pident;
    t_fdm->removeReadFD(fd); // pident might now be invalid (it isn't, but still)
    string empty;
    MT->sendEvent(tmp, &empty); // this conveys error status
  }
}

static void handleTCPClientWritable(int fd, FDMultiplexer::funcparam_t& var)
{
  PacketID* pid=any_cast<PacketID>(&var);
  ssize_t ret=send(fd, pid->outMSG.c_str() + pid->outPos, pid->outMSG.size() - pid->outPos,0);
  if(ret > 0) {
    pid->outPos+=(ssize_t)ret;
    if(pid->outPos==pid->outMSG.size()) {
      PacketID tmp=*pid;
      t_fdm->removeWriteFD(fd);
      MT->sendEvent(tmp, &tmp.outMSG);  // send back what we sent to convey everything is ok
    }
  }
  else {  // error or EOF
    PacketID tmp(*pid);
    t_fdm->removeWriteFD(fd);
    string sent;
    MT->sendEvent(tmp, &sent);         // we convey error status by sending empty string
  }
}

// resend event to everybody chained onto it
static void doResends(MT_t::waiters_t::iterator& iter, PacketID resend, const string& content)
{
  if(iter->key.chain.empty())
    return;
  //  cerr<<"doResends called!\n";
  for(PacketID::chain_t::iterator i=iter->key.chain.begin(); i != iter->key.chain.end() ; ++i) {
    resend.fd=-1;
    resend.id=*i;
    //    cerr<<"\tResending "<<content.size()<<" bytes for fd="<<resend.fd<<" and id="<<resend.id<<endl;

    MT->sendEvent(resend, &content);
    g_stats.chainResends++;
  }
}

static void handleUDPServerResponse(int fd, FDMultiplexer::funcparam_t& var)
{
  PacketID pid=any_cast<PacketID>(var);
  ssize_t len;
  std::string packet;
  packet.resize(g_outgoingEDNSBufsize);
  ComboAddress fromaddr;
  socklen_t addrlen=sizeof(fromaddr);

  len=recvfrom(fd, &packet.at(0), packet.size(), 0, (sockaddr *)&fromaddr, &addrlen);

  if(len < (ssize_t) sizeof(dnsheader)) {
    if(len < 0)
      ; //      cerr<<"Error on fd "<<fd<<": "<<stringerror()<<"\n";
    else {
      g_stats.serverParseError++;
      if(g_logCommonErrors)
        g_log<<Logger::Error<<"Unable to parse packet from remote UDP server "<< fromaddr.toString() <<
          ": packet smaller than DNS header"<<endl;
    }

    t_udpclientsocks->returnSocket(fd);
    string empty;

    MT_t::waiters_t::iterator iter=MT->d_waiters.find(pid);
    if(iter != MT->d_waiters.end())
      doResends(iter, pid, empty);

    MT->sendEvent(pid, &empty); // this denotes error (does lookup again.. at least L1 will be hot)
    return;
  }

  packet.resize(len);
  dnsheader dh;
  memcpy(&dh, &packet.at(0), sizeof(dh));

  PacketID pident;
  pident.remote=fromaddr;
  pident.id=dh.id;
  pident.fd=fd;

  if(!dh.qr && g_logCommonErrors) {
    g_log<<Logger::Notice<<"Not taking data from question on outgoing socket from "<< fromaddr.toStringWithPort()  <<endl;
  }

  if(!dh.qdcount || // UPC, Nominum, very old BIND on FormErr, NSD
     !dh.qr) {      // one weird server
    pident.domain.clear();
    pident.type = 0;
  }
  else {
    try {
      if(len > 12)
        pident.domain=DNSName(&packet.at(0), len, 12, false, &pident.type); // don't copy this from above - we need to do the actual read
    }
    catch(std::exception& e) {
      g_stats.serverParseError++; // won't be fed to lwres.cc, so we have to increment
      g_log<<Logger::Warning<<"Error in packet from remote nameserver "<< fromaddr.toStringWithPort() << ": "<<e.what() << endl;
      return;
    }
  }

  MT_t::waiters_t::iterator iter=MT->d_waiters.find(pident);
  if(iter != MT->d_waiters.end()) {
    doResends(iter, pident, packet);
  }

retryWithName:

  if(!MT->sendEvent(pident, &packet)) {
    /* we did not find a match for this response, something is wrong */

    // we do a full scan for outstanding queries on unexpected answers. not too bad since we only accept them on the right port number, which is hard enough to guess
    for(MT_t::waiters_t::iterator mthread=MT->d_waiters.begin(); mthread!=MT->d_waiters.end(); ++mthread) {
      if(pident.fd==mthread->key.fd && mthread->key.remote==pident.remote &&  mthread->key.type == pident.type &&
         pident.domain == mthread->key.domain) {
        mthread->key.nearMisses++;
      }

      // be a bit paranoid here since we're weakening our matching
      if(pident.domain.empty() && !mthread->key.domain.empty() && !pident.type && mthread->key.type &&
         pident.id  == mthread->key.id && mthread->key.remote == pident.remote) {
        // cerr<<"Empty response, rest matches though, sending to a waiter"<<endl;
        pident.domain = mthread->key.domain;
        pident.type = mthread->key.type;
        goto retryWithName; // note that this only passes on an error, lwres will still reject the packet
      }
    }
    g_stats.unexpectedCount++; // if we made it here, it really is an unexpected answer
    if(g_logCommonErrors) {
      g_log<<Logger::Warning<<"Discarding unexpected packet from "<<fromaddr.toStringWithPort()<<": "<< (pident.domain.empty() ? "<empty>" : pident.domain.toString())<<", "<<pident.type<<", "<<MT->d_waiters.size()<<" waiters"<<endl;
    }
  }
  else if(fd >= 0) {
    /* we either found a waiter (1) or encountered an issue (-1), it's up to us to clean the socket anyway */
    t_udpclientsocks->returnSocket(fd);
  }
}

FDMultiplexer* getMultiplexer()
{
  FDMultiplexer* ret;
  for(const auto& i : FDMultiplexer::getMultiplexerMap()) {
    try {
      ret=i.second();
      return ret;
    }
    catch(FDMultiplexerException &fe) {
      g_log<<Logger::Error<<"Non-fatal error initializing possible multiplexer ("<<fe.what()<<"), falling back"<<endl;
    }
    catch(...) {
      g_log<<Logger::Error<<"Non-fatal error initializing possible multiplexer"<<endl;
    }
  }
  g_log<<Logger::Error<<"No working multiplexer found!"<<endl;
  exit(1);
}


static string* doReloadLuaScript()
{
  string fname= ::arg()["lua-dns-script"];
  try {
    if(fname.empty()) {
      t_pdl.reset();
      g_log<<Logger::Info<<t_id<<" Unloaded current lua script"<<endl;
      return new string("unloaded\n");
    }
    else {
      t_pdl = std::make_shared<RecursorLua4>();
      t_pdl->loadFile(fname);
    }
  }
  catch(std::exception& e) {
    g_log<<Logger::Error<<t_id<<" Retaining current script, error from '"<<fname<<"': "<< e.what() <<endl;
    return new string("retaining current script, error from '"+fname+"': "+e.what()+"\n");
  }

  g_log<<Logger::Warning<<t_id<<" (Re)loaded lua script from '"<<fname<<"'"<<endl;
  return new string("(re)loaded '"+fname+"'\n");
}

string doQueueReloadLuaScript(vector<string>::const_iterator begin, vector<string>::const_iterator end)
{
  if(begin != end)
    ::arg().set("lua-dns-script") = *begin;

  return broadcastAccFunction<string>(doReloadLuaScript);
}

static string* pleaseUseNewTraceRegex(const std::string& newRegex)
try
{
  if(newRegex.empty()) {
    t_traceRegex.reset();
    return new string("unset\n");
  }
  else {
    t_traceRegex = std::make_shared<Regex>(newRegex);
    return new string("ok\n");
  }
}
catch(PDNSException& ae)
{
  return new string(ae.reason+"\n");
}

string doTraceRegex(vector<string>::const_iterator begin, vector<string>::const_iterator end)
{
  return broadcastAccFunction<string>(boost::bind(pleaseUseNewTraceRegex, begin!=end ? *begin : ""));
}

static void checkLinuxIPv6Limits()
{
#ifdef __linux__
  string line;
  if(readFileIfThere("/proc/sys/net/ipv6/route/max_size", &line)) {
    int lim=std::stoi(line);
    if(lim < 16384) {
      g_log<<Logger::Error<<"If using IPv6, please raise sysctl net.ipv6.route.max_size, currently set to "<<lim<<" which is < 16384"<<endl;
    }
  }
#endif
}
static void checkOrFixFDS()
{
  unsigned int availFDs=getFilenumLimit(); 
  unsigned int wantFDs = g_maxMThreads * g_numWorkerThreads +25; // even healthier margin then before

  if(wantFDs > availFDs) {
    unsigned int hardlimit= getFilenumLimit(true);
    if(hardlimit >= wantFDs) {
      setFilenumLimit(wantFDs);
      g_log<<Logger::Warning<<"Raised soft limit on number of filedescriptors to "<<wantFDs<<" to match max-mthreads and threads settings"<<endl;
    }
    else {
      int newval = (hardlimit - 25) / g_numWorkerThreads;
      g_log<<Logger::Warning<<"Insufficient number of filedescriptors available for max-mthreads*threads setting! ("<<hardlimit<<" < "<<wantFDs<<"), reducing max-mthreads to "<<newval<<endl;
      g_maxMThreads = newval;
      setFilenumLimit(hardlimit);
    }
  }
}

static void* recursorThread(unsigned int tid, const string& threadName);

static void* pleaseSupplantACLs(std::shared_ptr<NetmaskGroup> ng)
{
  t_allowFrom = ng;
  return nullptr;
}

int g_argc;
char** g_argv;

void parseACLs()
{
  static bool l_initialized;

  if(l_initialized) { // only reload configuration file on second call
    string configname=::arg()["config-dir"]+"/recursor.conf";
    if(::arg()["config-name"]!="") {
      configname=::arg()["config-dir"]+"/recursor-"+::arg()["config-name"]+".conf";
    }
    cleanSlashes(configname);

    if(!::arg().preParseFile(configname.c_str(), "allow-from-file"))
      throw runtime_error("Unable to re-parse configuration file '"+configname+"'");
    ::arg().preParseFile(configname.c_str(), "allow-from", LOCAL_NETS);
    ::arg().preParseFile(configname.c_str(), "include-dir");
    ::arg().preParse(g_argc, g_argv, "include-dir");

    // then process includes
    std::vector<std::string> extraConfigs;
    ::arg().gatherIncludes(extraConfigs);

    for(const std::string& fn : extraConfigs) {
      if(!::arg().preParseFile(fn.c_str(), "allow-from-file", ::arg()["allow-from-file"]))
	throw runtime_error("Unable to re-parse configuration file include '"+fn+"'");
      if(!::arg().preParseFile(fn.c_str(), "allow-from", ::arg()["allow-from"]))
	throw runtime_error("Unable to re-parse configuration file include '"+fn+"'");
    }

    ::arg().preParse(g_argc, g_argv, "allow-from-file");
    ::arg().preParse(g_argc, g_argv, "allow-from");
  }

  std::shared_ptr<NetmaskGroup> oldAllowFrom = t_allowFrom;
  std::shared_ptr<NetmaskGroup> allowFrom = std::make_shared<NetmaskGroup>();

  if(!::arg()["allow-from-file"].empty()) {
    string line;
    ifstream ifs(::arg()["allow-from-file"].c_str());
    if(!ifs) {
      throw runtime_error("Could not open '"+::arg()["allow-from-file"]+"': "+stringerror());
    }

    string::size_type pos;
    while(getline(ifs,line)) {
      pos=line.find('#');
      if(pos!=string::npos)
        line.resize(pos);
      trim(line);
      if(line.empty())
        continue;

      allowFrom->addMask(line);
    }
    g_log<<Logger::Warning<<"Done parsing " << allowFrom->size() <<" allow-from ranges from file '"<<::arg()["allow-from-file"]<<"' - overriding 'allow-from' setting"<<endl;
  }
  else if(!::arg()["allow-from"].empty()) {
    vector<string> ips;
    stringtok(ips, ::arg()["allow-from"], ", ");

    g_log<<Logger::Warning<<"Only allowing queries from: ";
    for(vector<string>::const_iterator i = ips.begin(); i!= ips.end(); ++i) {
      allowFrom->addMask(*i);
      if(i!=ips.begin())
        g_log<<Logger::Warning<<", ";
      g_log<<Logger::Warning<<*i;
    }
    g_log<<Logger::Warning<<endl;
  }
  else {
    if(::arg()["local-address"]!="127.0.0.1" && ::arg().asNum("local-port")==53)
      g_log<<Logger::Warning<<"WARNING: Allowing queries from all IP addresses - this can be a security risk!"<<endl;
    allowFrom = nullptr;
  }

  g_initialAllowFrom = allowFrom;
  broadcastFunction(boost::bind(pleaseSupplantACLs, allowFrom));
  oldAllowFrom = nullptr;

  l_initialized = true;
}


static void setupDelegationOnly()
{
  vector<string> parts;
  stringtok(parts, ::arg()["delegation-only"], ", \t");
  for(const auto& p : parts) {
    SyncRes::addDelegationOnly(DNSName(p));
  }
}

static std::map<unsigned int, std::set<int> > parseCPUMap()
{
  std::map<unsigned int, std::set<int> > result;

  const std::string value = ::arg()["cpu-map"];

  if (!value.empty() && !isSettingThreadCPUAffinitySupported()) {
    g_log<<Logger::Warning<<"CPU mapping requested but not supported, skipping"<<endl;
    return result;
  }

  std::vector<std::string> parts;

  stringtok(parts, value, " \t");

  for(const auto& part : parts) {
    if (part.find('=') == string::npos)
      continue;

    try {
      auto headers = splitField(part, '=');
      trim(headers.first);
      trim(headers.second);

      unsigned int threadId = pdns_stou(headers.first);
      std::vector<std::string> cpus;

      stringtok(cpus, headers.second, ",");

      for(const auto& cpu : cpus) {
        int cpuId = std::stoi(cpu);

        result[threadId].insert(cpuId);
      }
    }
    catch(const std::exception& e) {
      g_log<<Logger::Error<<"Error parsing cpu-map entry '"<<part<<"': "<<e.what()<<endl;
    }
  }

  return result;
}

static void setCPUMap(const std::map<unsigned int, std::set<int> >& cpusMap, unsigned int n, pthread_t tid)
{
  const auto& cpuMapping = cpusMap.find(n);
  if (cpuMapping != cpusMap.cend()) {
    int rc = mapThreadToCPUList(tid, cpuMapping->second);
    if (rc == 0) {
      g_log<<Logger::Info<<"CPU affinity for worker "<<n<<" has been set to CPU map:";
      for (const auto cpu : cpuMapping->second) {
        g_log<<Logger::Info<<" "<<cpu;
      }
      g_log<<Logger::Info<<endl;
    }
    else {
      g_log<<Logger::Warning<<"Error setting CPU affinity for worker "<<n<<" to CPU map:";
      for (const auto cpu : cpuMapping->second) {
        g_log<<Logger::Info<<" "<<cpu;
      }
      g_log<<Logger::Info<<strerror(rc)<<endl;
    }
  }
}

#ifdef NOD_ENABLED
static void setupNODThread()
{
  if (g_nodEnabled) {
    uint32_t num_cells = ::arg().asNum("new-domain-db-size");
    t_nodDBp = std::make_shared<nod::NODDB>(num_cells);
    try {
      t_nodDBp->setCacheDir(::arg()["new-domain-history-dir"]);
    }
    catch (const PDNSException& e) {
      g_log<<Logger::Error<<"new-domain-history-dir (" << ::arg()["new-domain-history-dir"] << ") is not readable or does not exist"<<endl;
      _exit(1);
    }
    if (!t_nodDBp->init()) {
      g_log<<Logger::Error<<"Could not initialize domain tracking"<<endl;
      _exit(1);
    }
    std::thread t(nod::NODDB::startHousekeepingThread, t_nodDBp, std::this_thread::get_id());
    t.detach();
    g_nod_pbtag = ::arg()["new-domain-pb-tag"];
  }
  if (g_udrEnabled) {
    uint32_t num_cells = ::arg().asNum("unique-response-db-size");
    t_udrDBp = std::make_shared<nod::UniqueResponseDB>(num_cells);
    try {
      t_udrDBp->setCacheDir(::arg()["unique-response-history-dir"]);
    }
    catch (const PDNSException& e) {
      g_log<<Logger::Error<<"unique-response-history-dir (" << ::arg()["unique-response-history-dir"] << ") is not readable or does not exist"<<endl;
      _exit(1);
    }
    if (!t_udrDBp->init()) {
      g_log<<Logger::Error<<"Could not initialize unique response tracking"<<endl;
      _exit(1);
    }
    std::thread t(nod::UniqueResponseDB::startHousekeepingThread, t_udrDBp, std::this_thread::get_id());
    t.detach();
    g_udr_pbtag = ::arg()["unique-response-pb-tag"];
  }
}

void parseNODWhitelist(const std::string& wlist)
{
  vector<string> parts;
  stringtok(parts, wlist, ",; ");
  for(const auto& a : parts) {
    g_nodDomainWL.add(DNSName(a));
  }
}

static void setupNODGlobal()
{
  // Setup NOD subsystem
  g_nodEnabled = ::arg().mustDo("new-domain-tracking");
  g_nodLookupDomain = DNSName(::arg()["new-domain-lookup"]);
  g_nodLog = ::arg().mustDo("new-domain-log");
  parseNODWhitelist(::arg()["new-domain-whitelist"]);

  // Setup Unique DNS Response subsystem
  g_udrEnabled = ::arg().mustDo("unique-response-tracking");
  g_udrLog = ::arg().mustDo("unique-response-log");
}
#endif /* NOD_ENABLED */

static int serviceMain(int argc, char*argv[])
{
  g_log.setName(s_programname);
  g_log.disableSyslog(::arg().mustDo("disable-syslog"));
  g_log.setTimestamps(::arg().mustDo("log-timestamp"));

  if(!::arg()["logging-facility"].empty()) {
    int val=logFacilityToLOG(::arg().asNum("logging-facility") );
    if(val >= 0)
      g_log.setFacility(val);
    else
      g_log<<Logger::Error<<"Unknown logging facility "<<::arg().asNum("logging-facility") <<endl;
  }

  showProductVersion();

  g_disthashseed=dns_random(0xffffffff);

  checkLinuxIPv6Limits();
  try {
    vector<string> addrs;
    if(!::arg()["query-local-address6"].empty()) {
      SyncRes::s_doIPv6=true;
      g_log<<Logger::Warning<<"Enabling IPv6 transport for outgoing queries"<<endl;

      stringtok(addrs, ::arg()["query-local-address6"], ", ;");
      for(const string& addr : addrs) {
        g_localQueryAddresses6.push_back(ComboAddress(addr));
      }
    }
    else {
      g_log<<Logger::Warning<<"NOT using IPv6 for outgoing queries - set 'query-local-address6=::' to enable"<<endl;
    }
    addrs.clear();
    stringtok(addrs, ::arg()["query-local-address"], ", ;");
    for(const string& addr : addrs) {
      g_localQueryAddresses4.push_back(ComboAddress(addr));
    }
  }
  catch(std::exception& e) {
    g_log<<Logger::Error<<"Assigning local query addresses: "<<e.what();
    exit(99);
  }

  // keep this ABOVE loadRecursorLuaConfig!
  if(::arg()["dnssec"]=="off")
    g_dnssecmode=DNSSECMode::Off;
  else if(::arg()["dnssec"]=="process-no-validate")
    g_dnssecmode=DNSSECMode::ProcessNoValidate;
  else if(::arg()["dnssec"]=="process")
    g_dnssecmode=DNSSECMode::Process;
  else if(::arg()["dnssec"]=="validate")
    g_dnssecmode=DNSSECMode::ValidateAll;
  else if(::arg()["dnssec"]=="log-fail")
    g_dnssecmode=DNSSECMode::ValidateForLog;
  else {
    g_log<<Logger::Error<<"Unknown DNSSEC mode "<<::arg()["dnssec"]<<endl;
    exit(1);
  }

  g_signatureInceptionSkew = ::arg().asNum("signature-inception-skew");
  if (g_signatureInceptionSkew < 0) {
    g_log<<Logger::Error<<"A negative value for 'signature-inception-skew' is not allowed"<<endl;
    exit(1);
  }

  g_dnssecLogBogus = ::arg().mustDo("dnssec-log-bogus");
  g_maxNSEC3Iterations = ::arg().asNum("nsec3-max-iterations");

  g_maxCacheEntries = ::arg().asNum("max-cache-entries");
  g_maxPacketCacheEntries = ::arg().asNum("max-packetcache-entries");

  luaConfigDelayedThreads delayedLuaThreads;
  try {
    loadRecursorLuaConfig(::arg()["lua-config-file"], delayedLuaThreads);
  }
  catch (PDNSException &e) {
    g_log<<Logger::Error<<"Cannot load Lua configuration: "<<e.reason<<endl;
    exit(1);
  }

  parseACLs();
  initPublicSuffixList(::arg()["public-suffix-list-file"]);

  if(!::arg()["dont-query"].empty()) {
    vector<string> ips;
    stringtok(ips, ::arg()["dont-query"], ", ");
    ips.push_back("0.0.0.0");
    ips.push_back("::");

    g_log<<Logger::Warning<<"Will not send queries to: ";
    for(vector<string>::const_iterator i = ips.begin(); i!= ips.end(); ++i) {
      SyncRes::addDontQuery(*i);
      if(i!=ips.begin())
        g_log<<Logger::Warning<<", ";
      g_log<<Logger::Warning<<*i;
    }
    g_log<<Logger::Warning<<endl;
  }

  g_quiet=::arg().mustDo("quiet");

  /* this needs to be done before parseACLs(), which call broadcastFunction() */
  g_weDistributeQueries = ::arg().mustDo("pdns-distributes-queries");
  if(g_weDistributeQueries) {
    g_log<<Logger::Warning<<"PowerDNS Recursor itself will distribute queries over threads"<<endl;
  }

  setupDelegationOnly();
  g_outgoingEDNSBufsize=::arg().asNum("edns-outgoing-bufsize");

  if(::arg()["trace"]=="fail") {
    SyncRes::setDefaultLogMode(SyncRes::Store);
  }
  else if(::arg().mustDo("trace")) {
    SyncRes::setDefaultLogMode(SyncRes::Log);
    ::arg().set("quiet")="no";
    g_quiet=false;
    g_dnssecLOG=true;
  }
  string myHostname = getHostname();
  if (myHostname == "UNKNOWN"){
    g_log<<Logger::Warning<<"Unable to get the hostname, NSID and id.server values will be empty"<<endl;
    myHostname = "";
  }

  SyncRes::s_minimumTTL = ::arg().asNum("minimum-ttl-override");
  SyncRes::s_minimumECSTTL = ::arg().asNum("ecs-minimum-ttl-override");

  SyncRes::s_nopacketcache = ::arg().mustDo("disable-packetcache");

  SyncRes::s_maxnegttl=::arg().asNum("max-negative-ttl");
  SyncRes::s_maxbogusttl=::arg().asNum("max-cache-bogus-ttl");
  SyncRes::s_maxcachettl=max(::arg().asNum("max-cache-ttl"), 15);
  SyncRes::s_packetcachettl=::arg().asNum("packetcache-ttl");
  // Cap the packetcache-servfail-ttl to the packetcache-ttl
  uint32_t packetCacheServFailTTL = ::arg().asNum("packetcache-servfail-ttl");
  SyncRes::s_packetcacheservfailttl=(packetCacheServFailTTL > SyncRes::s_packetcachettl) ? SyncRes::s_packetcachettl : packetCacheServFailTTL;
  SyncRes::s_serverdownmaxfails=::arg().asNum("server-down-max-fails");
  SyncRes::s_serverdownthrottletime=::arg().asNum("server-down-throttle-time");
  SyncRes::s_serverID=::arg()["server-id"];
  SyncRes::s_maxqperq=::arg().asNum("max-qperq");
  SyncRes::s_maxtotusec=1000*::arg().asNum("max-total-msec");
  SyncRes::s_maxdepth=::arg().asNum("max-recursion-depth");
  SyncRes::s_rootNXTrust = ::arg().mustDo( "root-nx-trust");
  if(SyncRes::s_serverID.empty()) {
    SyncRes::s_serverID = myHostname;
  }

  SyncRes::s_ecsipv4limit = ::arg().asNum("ecs-ipv4-bits");
  SyncRes::s_ecsipv6limit = ::arg().asNum("ecs-ipv6-bits");
  SyncRes::clearECSStats();
  SyncRes::s_ecsipv4cachelimit = ::arg().asNum("ecs-ipv4-cache-bits");
  SyncRes::s_ecsipv6cachelimit = ::arg().asNum("ecs-ipv6-cache-bits");
  SyncRes::s_ecscachelimitttl = ::arg().asNum("ecs-cache-limit-ttl");

  SyncRes::s_qnameminimization = ::arg().mustDo("qname-minimization");
  SyncRes::s_hardenNXD = ::arg().mustDo("nothing-below-nxdomain");

  if (!::arg().isEmpty("ecs-scope-zero-address")) {
    ComboAddress scopeZero(::arg()["ecs-scope-zero-address"]);
    SyncRes::setECSScopeZeroAddress(Netmask(scopeZero, scopeZero.isIPv4() ? 32 : 128));
  }
  else {
    bool found = false;
    for (const auto& addr : g_localQueryAddresses4) {
      if (!IsAnyAddress(addr)) {
        SyncRes::setECSScopeZeroAddress(Netmask(addr, 32));
        found = true;
        break;
      }
    }
    if (!found) {
      for (const auto& addr : g_localQueryAddresses6) {
        if (!IsAnyAddress(addr)) {
          SyncRes::setECSScopeZeroAddress(Netmask(addr, 128));
          found = true;
          break;
        }
      }
      if (!found) {
        SyncRes::setECSScopeZeroAddress(Netmask("127.0.0.1/32"));
      }
    }
  }

  SyncRes::parseEDNSSubnetWhitelist(::arg()["edns-subnet-whitelist"]);
  SyncRes::parseEDNSSubnetAddFor(::arg()["ecs-add-for"]);
  g_useIncomingECS = ::arg().mustDo("use-incoming-edns-subnet");

  g_XPFAcl.toMasks(::arg()["xpf-allow-from"]);
  g_xpfRRCode = ::arg().asNum("xpf-rr-code");

  g_networkTimeoutMsec = ::arg().asNum("network-timeout");

  g_initialDomainMap = parseAuthAndForwards();

  g_latencyStatSize=::arg().asNum("latency-statistic-size");

  g_logCommonErrors=::arg().mustDo("log-common-errors");
  g_logRPZChanges = ::arg().mustDo("log-rpz-changes");

  g_anyToTcp = ::arg().mustDo("any-to-tcp");
  g_udpTruncationThreshold = ::arg().asNum("udp-truncation-threshold");

  g_lowercaseOutgoing = ::arg().mustDo("lowercase-outgoing");

  g_numDistributorThreads = ::arg().asNum("distributor-threads");
  g_numWorkerThreads = ::arg().asNum("threads");
  if (g_numWorkerThreads < 1) {
    g_log<<Logger::Warning<<"Asked to run with 0 threads, raising to 1 instead"<<endl;
    g_numWorkerThreads = 1;
  }

  g_numThreads = g_numDistributorThreads + g_numWorkerThreads;
  g_maxMThreads = ::arg().asNum("max-mthreads");


  int64_t maxInFlight = ::arg().asNum("max-concurrent-requests-per-tcp-connection");
  if (maxInFlight < 1 || maxInFlight > USHRT_MAX || maxInFlight >= g_maxMThreads) {
    g_log<<Logger::Warning<<"Asked to run with illegal max-concurrent-requests-per-tcp-connection, setting to default (10)"<<endl;
    TCPConnection::s_maxInFlight = 10;
  } else {
    TCPConnection::s_maxInFlight = maxInFlight;
  }
    

  g_gettagNeedsEDNSOptions = ::arg().mustDo("gettag-needs-edns-options");

  g_statisticsInterval = ::arg().asNum("statistics-interval");

  {
    SuffixMatchNode dontThrottleNames;
    vector<string> parts;
    stringtok(parts, ::arg()["dont-throttle-names"]);
    for (const auto &p : parts) {
      dontThrottleNames.add(DNSName(p));
    }
    g_dontThrottleNames.setState(dontThrottleNames);

    NetmaskGroup dontThrottleNetmasks;
    stringtok(parts, ::arg()["dont-throttle-netmasks"]);
    for (const auto &p : parts) {
      dontThrottleNetmasks.addMask(Netmask(p));
    }
    g_dontThrottleNetmasks.setState(dontThrottleNetmasks);
  }

  s_balancingFactor = ::arg().asDouble("distribution-load-factor");
  if (s_balancingFactor != 0.0 && s_balancingFactor < 1.0) {
    s_balancingFactor = 0.0;
    g_log<<Logger::Warning<<"Asked to run with a distribution-load-factor below 1.0, disabling it instead"<<endl;
  }

#ifdef SO_REUSEPORT
  g_reusePort = ::arg().mustDo("reuseport");
#endif

  s_threadInfos.resize(g_numDistributorThreads + g_numWorkerThreads + /* handler */ 1);

  if (g_reusePort) {
    if (g_weDistributeQueries) {
      /* first thread is the handler, then distributors */
      for (unsigned int threadId = 1; threadId <= g_numDistributorThreads; threadId++) {
        auto& deferredAdds = s_threadInfos.at(threadId).deferredAdds;
        auto& tcpSockets = s_threadInfos.at(threadId).tcpSockets;
        makeUDPServerSockets(deferredAdds);
        makeTCPServerSockets(deferredAdds, tcpSockets);
      }
    }
    else {
      /* first thread is the handler, there is no distributor here and workers are accepting queries */
      for (unsigned int threadId = 1; threadId <= g_numWorkerThreads; threadId++) {
        auto& deferredAdds = s_threadInfos.at(threadId).deferredAdds;
        auto& tcpSockets = s_threadInfos.at(threadId).tcpSockets;
        makeUDPServerSockets(deferredAdds);
        makeTCPServerSockets(deferredAdds, tcpSockets);
      }
    }
  }
  else {
    std::set<int> tcpSockets;
    /* we don't have reuseport so we can only open one socket per
       listening addr:port and everyone will listen on it */
    makeUDPServerSockets(g_deferredAdds);
    makeTCPServerSockets(g_deferredAdds, tcpSockets);

    /* every listener (so distributor if g_weDistributeQueries, workers otherwise)
       needs to listen to the shared sockets */
    if (g_weDistributeQueries) {
      /* first thread is the handler, then distributors */
      for (unsigned int threadId = 1; threadId <= g_numDistributorThreads; threadId++) {
        s_threadInfos.at(threadId).tcpSockets = tcpSockets;
      }
    }
    else {
      /* first thread is the handler, there is no distributor here and workers are accepting queries */
      for (unsigned int threadId = 1; threadId <= g_numWorkerThreads; threadId++) {
        s_threadInfos.at(threadId).tcpSockets = tcpSockets;
      }
    }
  }

#ifdef NOD_ENABLED
  // Setup newly observed domain globals
  setupNODGlobal();
#endif /* NOD_ENABLED */
  
  int forks;
  for(forks = 0; forks < ::arg().asNum("processes") - 1; ++forks) {
    if(!fork()) // we are child
      break;
  }

  if(::arg().mustDo("daemon")) {
    g_log<<Logger::Warning<<"Calling daemonize, going to background"<<endl;
    g_log.toConsole(Logger::Critical);
    daemonize();
  }
  if(Utility::getpid() == 1) {
    /* We are running as pid 1, register sigterm and sigint handler
     
      The Linux kernel will handle SIGTERM and SIGINT for all processes, except PID 1.
      It assumes that the processes running as pid 1 is an "init" like system.
      For years, this was a safe assumption, but containers change that: in
      most (all?) container implementations, the application itself is running
      as pid 1. This means that sending signals to those applications, will not
      be handled by default. Results might be "your container not responsing
      when asking it to stop", or "ctrl-c not working even when the app is
      running in the foreground inside a container".

      So TL;DR: If we're running pid 1 (container), we should handle SIGTERM and SIGINT ourselves */

    signal(SIGTERM,termIntHandler);
    signal(SIGINT,termIntHandler);
  } 

  signal(SIGUSR1,usr1Handler);
  signal(SIGUSR2,usr2Handler);
  signal(SIGPIPE,SIG_IGN);

  checkOrFixFDS();

#ifdef HAVE_LIBSODIUM
  if (sodium_init() == -1) {
    g_log<<Logger::Error<<"Unable to initialize sodium crypto library"<<endl;
    exit(99);
  }
#endif

  openssl_thread_setup();
  openssl_seed();
  /* setup rng before chroot */
  dns_random_init();

  if(::arg()["server-id"].empty()) {
    ::arg().set("server-id") = myHostname;
  }

  int newgid=0;
  if(!::arg()["setgid"].empty())
    newgid = strToGID(::arg()["setgid"]);
  int newuid=0;
  if(!::arg()["setuid"].empty())
    newuid = strToUID(::arg()["setuid"]);

  Utility::dropGroupPrivs(newuid, newgid);

  if (!::arg()["chroot"].empty()) {
#ifdef HAVE_SYSTEMD
     char *ns;
     ns = getenv("NOTIFY_SOCKET");
     if (ns != nullptr) {
       g_log<<Logger::Error<<"Unable to chroot when running from systemd. Please disable chroot= or set the 'Type' for this service to 'simple'"<<endl;
       exit(1);
     }
#endif
    if (chroot(::arg()["chroot"].c_str())<0 || chdir("/") < 0) {
       int err = errno;
       g_log<<Logger::Error<<"Unable to chroot to '"+::arg()["chroot"]+"': "<<strerror (err)<<", exiting"<<endl;
       exit(1);
    }
    else
      g_log<<Logger::Info<<"Chrooted to '"<<::arg()["chroot"]<<"'"<<endl;
  }

  s_pidfname=::arg()["socket-dir"]+"/"+s_programname+".pid";
  if(!s_pidfname.empty())
    unlink(s_pidfname.c_str()); // remove possible old pid file
  writePid();

  makeControlChannelSocket( ::arg().asNum("processes") > 1 ? forks : -1);

  Utility::dropUserPrivs(newuid);
  try {
    /* we might still have capabilities remaining, for example if we have been started as root
       without --setuid (please don't do that) or as an unprivileged user with ambient capabilities
       like CAP_NET_BIND_SERVICE.
    */
    dropCapabilities();
  }
  catch(const std::exception& e) {
    g_log<<Logger::Warning<<e.what()<<endl;
  }

  startLuaConfigDelayedThreads(delayedLuaThreads, g_luaconfs.getCopy().generation);

  makeThreadPipes();

  g_tcpTimeout=::arg().asNum("client-tcp-timeout");
  g_maxTCPPerClient=::arg().asNum("max-tcp-per-client");
  g_tcpMaxQueriesPerConn=::arg().asNum("max-tcp-queries-per-connection");
  s_maxUDPQueriesPerRound=::arg().asNum("max-udp-queries-per-round");

  g_useKernelTimestamp = ::arg().mustDo("protobuf-use-kernel-timestamp");

  blacklistStats(StatComponent::API, ::arg()["stats-api-blacklist"]);
  blacklistStats(StatComponent::Carbon, ::arg()["stats-carbon-blacklist"]);
  blacklistStats(StatComponent::RecControl, ::arg()["stats-rec-control-blacklist"]);
  blacklistStats(StatComponent::SNMP, ::arg()["stats-snmp-blacklist"]);

  if (::arg().mustDo("snmp-agent")) {
    g_snmpAgent = std::make_shared<RecursorSNMPAgent>("recursor", ::arg()["snmp-master-socket"]);
    g_snmpAgent->run();
  }

  int port = ::arg().asNum("udp-source-port-min");
  if(port < 1024 || port > 65535){
    g_log<<Logger::Error<<"Unable to launch, udp-source-port-min is not a valid port number"<<endl;
    exit(99); // this isn't going to fix itself either
  }
  s_minUdpSourcePort = port;
  port = ::arg().asNum("udp-source-port-max");
  if(port < 1024 || port > 65535 || port < s_minUdpSourcePort){
    g_log<<Logger::Error<<"Unable to launch, udp-source-port-max is not a valid port number or is smaller than udp-source-port-min"<<endl;
    exit(99); // this isn't going to fix itself either
  }
  s_maxUdpSourcePort = port;
  std::vector<string> parts {};
  stringtok(parts, ::arg()["udp-source-port-avoid"], ", ");
  for (const auto &part : parts)
  {
    port = std::stoi(part);
    if(port < 1024 || port > 65535){
      g_log<<Logger::Error<<"Unable to launch, udp-source-port-avoid contains an invalid port number: "<<part<<endl;
      exit(99); // this isn't going to fix itself either
    }
    s_avoidUdpSourcePorts.insert(port);
  }

  unsigned int currentThreadId = 1;
  const auto cpusMap = parseCPUMap();

  if(g_numThreads == 1) {
    g_log<<Logger::Warning<<"Operating unthreaded"<<endl;
#ifdef HAVE_SYSTEMD
    sd_notify(0, "READY=1");
#endif

    /* This thread handles the web server, carbon, statistics and the control channel */
    auto& handlerInfos = s_threadInfos.at(0);
    handlerInfos.isHandler = true;
    handlerInfos.thread = std::thread(recursorThread, 0, "main");

    setCPUMap(cpusMap, currentThreadId, pthread_self());

    auto& infos = s_threadInfos.at(currentThreadId);
    infos.isListener = true;
    infos.isWorker = true;
    recursorThread(currentThreadId++, "worker");
  }
  else {

    if (g_weDistributeQueries) {
      g_log<<Logger::Warning<<"Launching "<< g_numDistributorThreads <<" distributor threads"<<endl;
      for(unsigned int n=0; n < g_numDistributorThreads; ++n) {
        auto& infos = s_threadInfos.at(currentThreadId);
        infos.isListener = true;
        infos.thread = std::thread(recursorThread, currentThreadId++, "distr");

        setCPUMap(cpusMap, currentThreadId, infos.thread.native_handle());
      }
    }

    g_log<<Logger::Warning<<"Launching "<< g_numWorkerThreads <<" worker threads"<<endl;

    for(unsigned int n=0; n < g_numWorkerThreads; ++n) {
      auto& infos = s_threadInfos.at(currentThreadId);
      infos.isListener = g_weDistributeQueries ? false : true;
      infos.isWorker = true;
      infos.thread = std::thread(recursorThread, currentThreadId++, "worker");

      setCPUMap(cpusMap, currentThreadId, infos.thread.native_handle());
    }

#ifdef HAVE_SYSTEMD
    sd_notify(0, "READY=1");
#endif

    /* This thread handles the web server, carbon, statistics and the control channel */
    auto& infos = s_threadInfos.at(0);
    infos.isHandler = true;
    infos.thread = std::thread(recursorThread, 0, "web+stat");

    s_threadInfos.at(0).thread.join();
  }
  return 0;
}

static void* recursorThread(unsigned int n, const string& threadName)
try
{
  t_id=n;
  auto& threadInfo = s_threadInfos.at(t_id);

  static string threadPrefix = "pdns-r/";
  setThreadName(threadPrefix + threadName);

  SyncRes tmp(g_now); // make sure it allocates tsstorage before we do anything, like primeHints or so..
  SyncRes::setDomainMap(g_initialDomainMap);
  t_allowFrom = g_initialAllowFrom;
  t_udpclientsocks = std::unique_ptr<UDPClientSocks>(new UDPClientSocks());
  t_tcpClientCounts = std::unique_ptr<tcpClientCounts_t>(new tcpClientCounts_t());
  primeHints();

  t_packetCache = std::unique_ptr<RecursorPacketCache>(new RecursorPacketCache());

  g_log<<Logger::Warning<<"Done priming cache with root hints"<<endl;

#ifdef NOD_ENABLED
  if (threadInfo.isWorker)
    setupNODThread();
#endif /* NOD_ENABLED */

  /* the listener threads handle TCP queries */
  if(threadInfo.isWorker || threadInfo.isListener) {
    try {
      if(!::arg()["lua-dns-script"].empty()) {
        t_pdl = std::make_shared<RecursorLua4>();
        t_pdl->loadFile(::arg()["lua-dns-script"]);
        g_log<<Logger::Warning<<"Loaded 'lua' script from '"<<::arg()["lua-dns-script"]<<"'"<<endl;
      }
    }
    catch(std::exception &e) {
      g_log<<Logger::Error<<"Failed to load 'lua' script from '"<<::arg()["lua-dns-script"]<<"': "<<e.what()<<endl;
      _exit(99);
    }
  }

  unsigned int ringsize=::arg().asNum("stats-ringbuffer-entries") / g_numWorkerThreads;
  if(ringsize) {
    t_remotes = std::unique_ptr<addrringbuf_t>(new addrringbuf_t());
    if(g_weDistributeQueries)
      t_remotes->set_capacity(::arg().asNum("stats-ringbuffer-entries") / g_numDistributorThreads);
    else
      t_remotes->set_capacity(ringsize);
    t_servfailremotes = std::unique_ptr<addrringbuf_t>(new addrringbuf_t());
    t_servfailremotes->set_capacity(ringsize);
    t_bogusremotes = std::unique_ptr<addrringbuf_t>(new addrringbuf_t());
    t_bogusremotes->set_capacity(ringsize);
    t_largeanswerremotes = std::unique_ptr<addrringbuf_t>(new addrringbuf_t());
    t_largeanswerremotes->set_capacity(ringsize);
    t_timeouts = std::unique_ptr<addrringbuf_t>(new addrringbuf_t());
    t_timeouts->set_capacity(ringsize);

    t_queryring = std::unique_ptr<boost::circular_buffer<pair<DNSName, uint16_t> > >(new boost::circular_buffer<pair<DNSName, uint16_t> >());
    t_queryring->set_capacity(ringsize);
    t_servfailqueryring = std::unique_ptr<boost::circular_buffer<pair<DNSName, uint16_t> > >(new boost::circular_buffer<pair<DNSName, uint16_t> >());
    t_servfailqueryring->set_capacity(ringsize);
    t_bogusqueryring = std::unique_ptr<boost::circular_buffer<pair<DNSName, uint16_t> > >(new boost::circular_buffer<pair<DNSName, uint16_t> >());
    t_bogusqueryring->set_capacity(ringsize);
  }

  MT=std::unique_ptr<MTasker<PacketID,string> >(new MTasker<PacketID,string>(::arg().asNum("stack-size")));
  threadInfo.mt = MT.get();

#ifdef HAVE_PROTOBUF
  /* start protobuf export threads if needed */
  auto luaconfsLocal = g_luaconfs.getLocal();
  checkProtobufExport(luaconfsLocal);
  checkOutgoingProtobufExport(luaconfsLocal);
#endif /* HAVE_PROTOBUF */
#ifdef HAVE_FSTRM
  checkFrameStreamExport(luaconfsLocal);
#endif

  PacketID pident;

  t_fdm=getMultiplexer();

  if(threadInfo.isHandler) {
    if(::arg().mustDo("webserver")) {
      g_log<<Logger::Warning << "Enabling web server" << endl;
      try {
        new RecursorWebServer(t_fdm);
      }
      catch(PDNSException &e) {
        g_log<<Logger::Error<<"Exception: "<<e.reason<<endl;
        exit(99);
      }
    }
    g_log<<Logger::Info<<"Enabled '"<< t_fdm->getName() << "' multiplexer"<<endl;
  }
  else {

    t_fdm->addReadFD(threadInfo.pipes.readToThread, handlePipeRequest);
    t_fdm->addReadFD(threadInfo.pipes.readQueriesToThread, handlePipeRequest);

    if (threadInfo.isListener) {
      if (g_reusePort) {
        /* then every listener has its own FDs */
        for(const auto deferred : threadInfo.deferredAdds) {
          t_fdm->addReadFD(deferred.first, deferred.second);
        }
      }
      else {
        /* otherwise all listeners are listening on the same ones */
        for(const auto deferred : g_deferredAdds) {
          t_fdm->addReadFD(deferred.first, deferred.second);
        }
      }
    }
  }

  registerAllStats();

  if(threadInfo.isHandler) {
    t_fdm->addReadFD(s_rcc.d_fd, handleRCC); // control channel
  }

  unsigned int maxTcpClients=::arg().asNum("max-tcp-clients");

  bool listenOnTCP(true);

  time_t last_stat = 0;
  time_t last_carbon=0, last_lua_maintenance=0;
  time_t carbonInterval=::arg().asNum("carbon-interval");
  time_t luaMaintenanceInterval=::arg().asNum("lua-maintenance-interval");
  counter.store(0); // used to periodically execute certain tasks
  for(;;) {
    while(MT->schedule(&g_now)); // MTasker letting the mthreads do their thing

    if(!(counter%500)) {
      MT->makeThread(houseKeeping, 0);
    }

    if(!(counter%55)) {
      typedef vector<pair<int, FDMultiplexer::funcparam_t> > expired_t;
      expired_t expired=t_fdm->getTimeouts(g_now);

      for(expired_t::iterator i=expired.begin() ; i != expired.end(); ++i) {
        shared_ptr<TCPConnection> conn=any_cast<shared_ptr<TCPConnection> >(i->second);
        if(g_logCommonErrors)
          g_log<<Logger::Warning<<"Timeout from remote TCP client "<< conn->d_remote.toStringWithPort() <<endl;
        t_fdm->removeReadFD(i->first);
      }
    }

    counter++;

    if(threadInfo.isHandler) {
      if(statsWanted || (g_statisticsInterval > 0 && (g_now.tv_sec - last_stat) >= g_statisticsInterval)) {
        doStats();
        last_stat = g_now.tv_sec;
      }

      Utility::gettimeofday(&g_now, 0);

      if((g_now.tv_sec - last_carbon) >= carbonInterval) {
        MT->makeThread(doCarbonDump, 0);
        last_carbon = g_now.tv_sec;
      }
    }
    if (t_pdl != nullptr) {
      // lua-dns-script directive is present, call the maintenance callback if needed
      /* remember that the listener threads handle TCP queries */
      if (threadInfo.isWorker || threadInfo.isListener) {
        // Only on threads processing queries
        if(g_now.tv_sec - last_lua_maintenance >= luaMaintenanceInterval) {
          t_pdl->maintenance();
          last_lua_maintenance = g_now.tv_sec;
        }
      }
    }

    t_fdm->run(&g_now);
    // 'run' updates g_now for us

    if(threadInfo.isListener) {
      if(listenOnTCP) {
        if(TCPConnection::getCurrentConnections() > maxTcpClients) {  // shutdown, too many connections
          for(const auto fd : threadInfo.tcpSockets) {
            t_fdm->removeReadFD(fd);
          }
          listenOnTCP=false;
        }
      }
      else {
        if(TCPConnection::getCurrentConnections() <= maxTcpClients) {  // reenable
          for(const auto fd : threadInfo.tcpSockets) {
            t_fdm->addReadFD(fd, handleNewTCPQuestion);
          }
          listenOnTCP=true;
        }
      }
    }
  }
}
catch(PDNSException &ae) {
  g_log<<Logger::Error<<"Exception: "<<ae.reason<<endl;
  return 0;
}
catch(std::exception &e) {
   g_log<<Logger::Error<<"STL Exception: "<<e.what()<<endl;
   return 0;
}
catch(...) {
   g_log<<Logger::Error<<"any other exception in main: "<<endl;
   return 0;
}


int main(int argc, char **argv)
{
  g_argc = argc;
  g_argv = argv;
  g_stats.startupTime=time(0);
  Utility::srandom();
  versionSetProduct(ProductRecursor);
  reportBasicTypes();
  reportOtherTypes();

  int ret = EXIT_SUCCESS;

  try {
    ::arg().set("stack-size","stack size per mthread")="200000";
    ::arg().set("soa-minimum-ttl","Don't change")="0";
    ::arg().set("no-shuffle","Don't change")="off";
    ::arg().set("local-port","port to listen on")="53";
    ::arg().set("local-address","IP addresses to listen on, separated by spaces or commas. Also accepts ports.")="127.0.0.1";
    ::arg().setSwitch("non-local-bind", "Enable binding to non-local addresses by using FREEBIND / BINDANY socket options")="no";
    ::arg().set("trace","if we should output heaps of logging. set to 'fail' to only log failing domains")="off";
    ::arg().set("dnssec", "DNSSEC mode: off/process-no-validate (default)/process/log-fail/validate")="process-no-validate";
    ::arg().set("dnssec-log-bogus", "Log DNSSEC bogus validations")="no";
    ::arg().set("signature-inception-skew", "Allow the signature inception to be off by this number of seconds")="60";
    ::arg().set("daemon","Operate as a daemon")="no";
    ::arg().setSwitch("write-pid","Write a PID file")="yes";
    ::arg().set("loglevel","Amount of logging. Higher is more. Do not set below 3")="6";
    ::arg().set("disable-syslog","Disable logging to syslog, useful when running inside a supervisor that logs stdout")="no";
    ::arg().set("log-timestamp","Print timestamps in log lines, useful to disable when running with a tool that timestamps stdout already")="yes";
    ::arg().set("log-common-errors","If we should log rather common errors")="no";
    ::arg().set("chroot","switch to chroot jail")="";
    ::arg().set("setgid","If set, change group id to this gid for more security"
#ifdef HAVE_SYSTEMD
#define SYSTEMD_SETID_MSG ". When running inside systemd, use the User and Group settings in the unit-file!"
        SYSTEMD_SETID_MSG
#endif
        )="";
    ::arg().set("setuid","If set, change user id to this uid for more security"
#ifdef HAVE_SYSTEMD
        SYSTEMD_SETID_MSG
#endif
        )="";
    ::arg().set("network-timeout", "Wait this number of milliseconds for network i/o")="1500";
    ::arg().set("threads", "Launch this number of threads")="2";
    ::arg().set("distributor-threads", "Launch this number of distributor threads, distributing queries to other threads")="0";
    ::arg().set("processes", "Launch this number of processes (EXPERIMENTAL, DO NOT CHANGE)")="1"; // if we un-experimental this, need to fix openssl rand seeding for multiple PIDs!
    ::arg().set("config-name","Name of this virtual configuration - will rename the binary image")="";
    ::arg().set("api-config-dir", "Directory where REST API stores config and zones") = "";
    ::arg().set("api-key", "Static pre-shared authentication key for access to the REST API") = "";
    ::arg().setSwitch("webserver", "Start a webserver (for REST API)") = "no";
    ::arg().set("webserver-address", "IP Address of webserver to listen on") = "127.0.0.1";
    ::arg().set("webserver-port", "Port of webserver to listen on") = "8082";
    ::arg().set("webserver-password", "Password required for accessing the webserver") = "";
    ::arg().set("webserver-allow-from","Webserver access is only allowed from these subnets")="127.0.0.1,::1";
    ::arg().set("webserver-loglevel", "Amount of logging in the webserver (none, normal, detailed)") = "normal";
    ::arg().set("carbon-ourname", "If set, overrides our reported hostname for carbon stats")="";
    ::arg().set("carbon-server", "If set, send metrics in carbon (graphite) format to this server IP address")="";
    ::arg().set("carbon-interval", "Number of seconds between carbon (graphite) updates")="30";
    ::arg().set("carbon-namespace", "If set overwrites the first part of the carbon string")="pdns";
    ::arg().set("carbon-instance", "If set overwrites the the instance name default")="recursor";

    ::arg().set("statistics-interval", "Number of seconds between printing of recursor statistics, 0 to disable")="1800";
    ::arg().set("quiet","Suppress logging of questions and answers")="";
    ::arg().set("logging-facility","Facility to log messages as. 0 corresponds to local0")="";
    ::arg().set("config-dir","Location of configuration directory (recursor.conf)")=SYSCONFDIR;
    ::arg().set("socket-owner","Owner of socket")="";
    ::arg().set("socket-group","Group of socket")="";
    ::arg().set("socket-mode", "Permissions for socket")="";

    ::arg().set("socket-dir",string("Where the controlsocket will live, ")+LOCALSTATEDIR+"/pdns-recursor when unset and not chrooted" )="";
    ::arg().set("delegation-only","Which domains we only accept delegations from")="";
    ::arg().set("query-local-address","Source IP address for sending queries")="0.0.0.0";
    ::arg().set("query-local-address6","Source IPv6 address for sending queries. IF UNSET, IPv6 WILL NOT BE USED FOR OUTGOING QUERIES")="";
    ::arg().set("client-tcp-timeout","Timeout in seconds when talking to TCP clients")="2";
    ::arg().set("max-mthreads", "Maximum number of simultaneous Mtasker threads")="2048";
    ::arg().set("max-tcp-clients","Maximum number of simultaneous TCP clients")="128";
    ::arg().set("max-concurrent-requests-per-tcp-connection", "Maximum number of requests handled concurrently per TCP connection") = "10";
    ::arg().set("server-down-max-fails","Maximum number of consecutive timeouts (and unreachables) to mark a server as down ( 0 => disabled )")="64";
    ::arg().set("server-down-throttle-time","Number of seconds to throttle all queries to a server after being marked as down")="60";
    ::arg().set("dont-throttle-names", "Do not throttle nameservers with this name or suffix")="";
    ::arg().set("dont-throttle-netmasks", "Do not throttle nameservers with this IP netmask")="";
    ::arg().set("hint-file", "If set, load root hints from this file")="";
    ::arg().set("max-cache-entries", "If set, maximum number of entries in the main cache")="1000000";
    ::arg().set("max-negative-ttl", "maximum number of seconds to keep a negative cached entry in memory")="3600";
    ::arg().set("max-cache-bogus-ttl", "maximum number of seconds to keep a Bogus (positive or negative) cached entry in memory")="3600";
    ::arg().set("max-cache-ttl", "maximum number of seconds to keep a cached entry in memory")="86400";
    ::arg().set("packetcache-ttl", "maximum number of seconds to keep a cached entry in packetcache")="3600";
    ::arg().set("max-packetcache-entries", "maximum number of entries to keep in the packetcache")="500000";
    ::arg().set("packetcache-servfail-ttl", "maximum number of seconds to keep a cached servfail entry in packetcache")="60";
    ::arg().set("server-id", "Returned when queried for 'id.server' TXT or NSID, defaults to hostname, set custom or 'disabled'")="";
    ::arg().set("stats-ringbuffer-entries", "maximum number of packets to store statistics for")="10000";
    ::arg().set("version-string", "string reported on version.pdns or version.bind")=fullVersionString();
    ::arg().set("allow-from", "If set, only allow these comma separated netmasks to recurse")=LOCAL_NETS;
    ::arg().set("allow-from-file", "If set, load allowed netmasks from this file")="";
    ::arg().set("entropy-source", "If set, read entropy from this file")="/dev/urandom";
    ::arg().set("dont-query", "If set, do not query these netmasks for DNS data")=DONT_QUERY;
    ::arg().set("max-tcp-per-client", "If set, maximum number of TCP sessions per client (IP address)")="0";
    ::arg().set("max-tcp-queries-per-connection", "If set, maximum number of TCP queries in a TCP connection")="0";
    ::arg().set("spoof-nearmiss-max", "If non-zero, assume spoofing after this many near misses")="20";
    ::arg().set("single-socket", "If set, only use a single socket for outgoing queries")="off";
    ::arg().set("auth-zones", "Zones for which we have authoritative data, comma separated domain=file pairs ")="";
    ::arg().set("lua-config-file", "More powerful configuration options")="";
    ::arg().setSwitch("allow-trust-anchor-query", "Allow queries for trustanchor.server CH TXT and negativetrustanchor.server CH TXT")="no";

    ::arg().set("forward-zones", "Zones for which we forward queries, comma separated domain=ip pairs")="";
    ::arg().set("forward-zones-recurse", "Zones for which we forward queries with recursion bit, comma separated domain=ip pairs")="";
    ::arg().set("forward-zones-file", "File with (+)domain=ip pairs for forwarding")="";
    ::arg().set("export-etc-hosts", "If we should serve up contents from /etc/hosts")="off";
    ::arg().set("export-etc-hosts-search-suffix", "Also serve up the contents of /etc/hosts with this suffix")="";
    ::arg().set("etc-hosts-file", "Path to 'hosts' file")="/etc/hosts";
    ::arg().set("serve-rfc1918", "If we should be authoritative for RFC 1918 private IP space")="yes";
    ::arg().set("lua-dns-script", "Filename containing an optional 'lua' script that will be used to modify dns answers")="";
    ::arg().set("lua-maintenance-interval", "Number of seconds between calls to the lua user defined maintenance() function")="1";
    ::arg().set("latency-statistic-size","Number of latency values to calculate the qa-latency average")="10000";
    ::arg().setSwitch( "disable-packetcache", "Disable packetcache" )= "no";
    ::arg().set("ecs-ipv4-bits", "Number of bits of IPv4 address to pass for EDNS Client Subnet")="24";
    ::arg().set("ecs-ipv4-cache-bits", "Maximum number of bits of IPv4 mask to cache ECS response")="24";
    ::arg().set("ecs-ipv6-bits", "Number of bits of IPv6 address to pass for EDNS Client Subnet")="56";
    ::arg().set("ecs-ipv6-cache-bits", "Maximum number of bits of IPv6 mask to cache ECS response")="56";
    ::arg().set("ecs-minimum-ttl-override", "Set under adverse conditions, a minimum TTL for records in ECS-specific answers")="0";
    ::arg().set("ecs-cache-limit-ttl", "Minimum TTL to cache ECS response")="0";
    ::arg().set("edns-subnet-whitelist", "List of netmasks and domains that we should enable EDNS subnet for")="";
    ::arg().set("ecs-add-for", "List of client netmasks for which EDNS Client Subnet will be added")="0.0.0.0/0, ::/0, " LOCAL_NETS_INVERSE;
    ::arg().set("ecs-scope-zero-address", "Address to send to whitelisted authoritative servers for incoming queries with ECS prefix-length source of 0")="";
    ::arg().setSwitch( "use-incoming-edns-subnet", "Pass along received EDNS Client Subnet information")="no";
    ::arg().setSwitch( "pdns-distributes-queries", "If PowerDNS itself should distribute queries over threads")="yes";
    ::arg().setSwitch( "root-nx-trust", "If set, believe that an NXDOMAIN from the root means the TLD does not exist")="yes";
    ::arg().setSwitch( "any-to-tcp","Answer ANY queries with tc=1, shunting to TCP" )="no";
    ::arg().setSwitch( "lowercase-outgoing","Force outgoing questions to lowercase")="no";
    ::arg().setSwitch("gettag-needs-edns-options", "If EDNS Options should be extracted before calling the gettag() hook")="no";
    ::arg().set("udp-truncation-threshold", "Maximum UDP response size before we truncate")="1232";
    ::arg().set("edns-outgoing-bufsize", "Outgoing EDNS buffer size")="1232";
    ::arg().set("minimum-ttl-override", "Set under adverse conditions, a minimum TTL")="0";
    ::arg().set("max-qperq", "Maximum outgoing queries per query")="50";
    ::arg().set("max-total-msec", "Maximum total wall-clock time per query in milliseconds, 0 for unlimited")="7000";
    ::arg().set("max-recursion-depth", "Maximum number of internal recursion calls per query, 0 for unlimited")="40";
    ::arg().set("max-udp-queries-per-round", "Maximum number of UDP queries processed per recvmsg() round, before returning back to normal processing")="10000";
    ::arg().set("protobuf-use-kernel-timestamp", "Compute the latency of queries in protobuf messages by using the timestamp set by the kernel when the query was received (when available)")="";
    ::arg().set("distribution-pipe-buffer-size", "Size in bytes of the internal buffer of the pipe used by the distributor to pass incoming queries to a worker thread")="0";

    ::arg().set("include-dir","Include *.conf files from this directory")="";
    ::arg().set("security-poll-suffix","Domain name from which to query security update notifications")="secpoll.powerdns.com.";
    
    ::arg().setSwitch("reuseport","Enable SO_REUSEPORT allowing multiple recursors processes to listen to 1 address")="no";

    ::arg().setSwitch("snmp-agent", "If set, register as an SNMP agent")="no";
    ::arg().set("snmp-master-socket", "If set and snmp-agent is set, the socket to use to register to the SNMP master")="";

    std::string defaultBlacklistedStats = "cache-bytes, packetcache-bytes, special-memory-usage";
    for (size_t idx = 0; idx < 32; idx++) {
      defaultBlacklistedStats += ", ecs-v4-response-bits-" + std::to_string(idx + 1);
    }
    for (size_t idx = 0; idx < 128; idx++) {
      defaultBlacklistedStats += ", ecs-v6-response-bits-" + std::to_string(idx + 1);
    }
    ::arg().set("stats-api-blacklist", "List of statistics that are disabled when retrieving the complete list of statistics via the API")=defaultBlacklistedStats;
    ::arg().set("stats-carbon-blacklist", "List of statistics that are prevented from being exported via Carbon")=defaultBlacklistedStats;
    ::arg().set("stats-rec-control-blacklist", "List of statistics that are prevented from being exported via rec_control get-all")=defaultBlacklistedStats;
    ::arg().set("stats-snmp-blacklist", "List of statistics that are prevented from being exported via SNMP")=defaultBlacklistedStats;

    ::arg().set("tcp-fast-open", "Enable TCP Fast Open support on the listening sockets, using the supplied numerical value as the queue size")="0";
    ::arg().set("nsec3-max-iterations", "Maximum number of iterations allowed for an NSEC3 record")="2500";

    ::arg().set("cpu-map", "Thread to CPU mapping, space separated thread-id=cpu1,cpu2..cpuN pairs")="";

    ::arg().setSwitch("log-rpz-changes", "Log additions and removals to RPZ zones at Info level")="no";

    ::arg().set("xpf-allow-from","XPF information is only processed from these subnets")="";
    ::arg().set("xpf-rr-code","XPF option code to use")="0";

    ::arg().set("udp-source-port-min", "Minimum UDP port to bind on")="1024";
    ::arg().set("udp-source-port-max", "Maximum UDP port to bind on")="65535";
    ::arg().set("udp-source-port-avoid", "List of comma separated UDP port number to avoid")="11211";
    ::arg().set("rng", "Specify random number generator to use. Valid values are auto,sodium,openssl,getrandom,arc4random,urandom.")="auto";
    ::arg().set("public-suffix-list-file", "Path to the Public Suffix List file, if any")="";
    ::arg().set("distribution-load-factor", "The load factor used when PowerDNS is distributing queries to worker threads")="0.0";
    ::arg().setSwitch("qname-minimization", "Use Query Name Minimization")="no";
    ::arg().setSwitch("nothing-below-nxdomain", "When an NXDOMAIN exists in cache for a name with fewer labels than the qname, send NXDOMAIN without doing a lookup (see RFC 8020)")="yes";
#ifdef NOD_ENABLED
    ::arg().set("new-domain-tracking", "Track newly observed domains (i.e. never seen before).")="no";
    ::arg().set("new-domain-log", "Log newly observed domains.")="yes";
    ::arg().set("new-domain-lookup", "Perform a DNS lookup newly observed domains as a subdomain of the configured domain")="";
    ::arg().set("new-domain-history-dir", "Persist new domain tracking data here to persist between restarts")=string(NODCACHEDIR)+"/nod";
    ::arg().set("new-domain-whitelist", "List of domains (and implicitly all subdomains) which will never be considered a new domain")="";
    ::arg().set("new-domain-db-size", "Size of the DB used to track new domains in terms of number of cells. Defaults to 67108864")="67108864";
    ::arg().set("new-domain-pb-tag", "If protobuf is configured, the tag to use for messages containing newly observed domains. Defaults to 'pdns-nod'")="pdns-nod";
    ::arg().set("unique-response-tracking", "Track unique responses (tuple of query name, type and RR).")="no";
    ::arg().set("unique-response-log", "Log unique responses")="yes";
    ::arg().set("unique-response-history-dir", "Persist unique response tracking data here to persist between restarts")=string(NODCACHEDIR)+"/udr";
    ::arg().set("unique-response-db-size", "Size of the DB used to track unique responses in terms of number of cells. Defaults to 67108864")="67108864";
    ::arg().set("unique-response-pb-tag", "If protobuf is configured, the tag to use for messages containing unique DNS responses. Defaults to 'pdns-udr'")="pdns-udr";
#endif /* NOD_ENABLED */
    ::arg().setCmd("help","Provide a helpful message");
    ::arg().setCmd("version","Print version string");
    ::arg().setCmd("config","Output blank configuration");
    g_log.toConsole(Logger::Info);
    ::arg().laxParse(argc,argv); // do a lax parse

    string configname=::arg()["config-dir"]+"/recursor.conf";
    if(::arg()["config-name"]!="") {
      configname=::arg()["config-dir"]+"/recursor-"+::arg()["config-name"]+".conf";
      s_programname+="-"+::arg()["config-name"];
    }
    cleanSlashes(configname);

    if(!::arg().getCommands().empty()) {
      cerr<<"Fatal: non-option";
      if (::arg().getCommands().size() > 1) {
        cerr<<"s";
      }
      cerr<<" (";
      bool first = true;
      for (auto const c : ::arg().getCommands()) {
        if (!first) {
          cerr<<", ";
        }
        first = false;
        cerr<<c;
      }
      cerr<<") on the command line, perhaps a '--setting=123' statement missed the '='?"<<endl;
      exit(99);
    }

    if(::arg().mustDo("config")) {
      cout<<::arg().configstring()<<endl;
      exit(0);
    }

    if(!::arg().file(configname.c_str()))
      g_log<<Logger::Warning<<"Unable to parse configuration file '"<<configname<<"'"<<endl;

    ::arg().parse(argc,argv);

    if( !::arg()["chroot"].empty() && !::arg()["api-config-dir"].empty() ) {
      g_log<<Logger::Error<<"Using chroot and enabling the API is not possible"<<endl;
      exit(EXIT_FAILURE);
    }

    if (::arg()["socket-dir"].empty()) {
      if (::arg()["chroot"].empty())
        ::arg().set("socket-dir") = std::string(LOCALSTATEDIR) + "/pdns-recursor";
      else
        ::arg().set("socket-dir") = "/";
    }

    ::arg().set("delegation-only")=toLower(::arg()["delegation-only"]);

    if(::arg().asNum("threads")==1) {
      if (::arg().mustDo("pdns-distributes-queries")) {
        g_log<<Logger::Warning<<"Only one thread, no need to distribute queries ourselves"<<endl;
        ::arg().set("pdns-distributes-queries")="no";
      }
    }

    if(::arg().mustDo("pdns-distributes-queries") && ::arg().asNum("distributor-threads") <= 0) {
      g_log<<Logger::Warning<<"Asked to run with pdns-distributes-queries set but no distributor threads, raising to 1"<<endl;
      ::arg().set("distributor-threads")="1";
    }

    if (!::arg().mustDo("pdns-distributes-queries")) {
      ::arg().set("distributor-threads")="0";
    }

    if(::arg().mustDo("help")) {
      cout<<"syntax:"<<endl<<endl;
      cout<<::arg().helpstring(::arg()["help"])<<endl;
      exit(0);
    }
    if(::arg().mustDo("version")) {
      showProductVersion();
      showBuildConfiguration();
      exit(0);
    }

    Logger::Urgency logUrgency = (Logger::Urgency)::arg().asNum("loglevel");

    if (logUrgency < Logger::Error)
      logUrgency = Logger::Error;
    if(!g_quiet && logUrgency < Logger::Info) { // Logger::Info=6, Logger::Debug=7
      logUrgency = Logger::Info;                // if you do --quiet=no, you need Info to also see the query log
    }
    g_log.setLoglevel(logUrgency);
    g_log.toConsole(logUrgency);

    serviceMain(argc, argv);
  }
  catch(PDNSException &ae) {
    g_log<<Logger::Error<<"Exception: "<<ae.reason<<endl;
    ret=EXIT_FAILURE;
  }
  catch(std::exception &e) {
    g_log<<Logger::Error<<"STL Exception: "<<e.what()<<endl;
    ret=EXIT_FAILURE;
  }
  catch(...) {
    g_log<<Logger::Error<<"any other exception in main: "<<endl;
    ret=EXIT_FAILURE;
  }

  return ret;
}
