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
#include "utility.hh"
#include "lwres.hh"
#include <iostream>
#include "dnsrecords.hh"
#include <cerrno>
#include "misc.hh"
#include <algorithm>
#include <sstream>
#include <cstring>
#include <string>
#include <vector>
#include "dns.hh"
#include "qtype.hh"
#include "pdnsexception.hh"
#include "arguments.hh"
#include "sstuff.hh"
#include "syncres.hh"
#include "dnswriter.hh"
#include "dnsparser.hh"
#include "logger.hh"
#include "dns_random.hh"
#include <boost/scoped_array.hpp>
#include <boost/algorithm/string.hpp>
#include "validate-recursor.hh"
#include "ednssubnet.hh"
#include "query-local-address.hh"
#include "tcpiohandler.hh"
#include "ednsoptions.hh"
#include "ednspadding.hh"
#include "rec-protozero.hh"
#include "uuid-utils.hh"
#include "rec-tcpout.hh"
#include "rec-cookiestore.hh"

static bool g_cookies = false;

std::string enableOutgoingCookies(bool flag, const string& unsupported)
{
  g_cookies = flag;
  if (g_cookies) {
    std::vector<std::string> parts;
    stringtok(parts, unsupported, ", ");
    std::string errors;
    addCookiesUnsupported(parts.begin(), parts.end(), errors);
    return errors;
  }
  return {};
}

thread_local TCPOutConnectionManager t_tcp_manager;
std::shared_ptr<Logr::Logger> g_slogout;
bool g_paddingOutgoing;
bool g_ECSHardening;

static LockGuarded<CookieStore> s_cookiestore;

uint64_t addCookiesUnsupported(vector<string>::iterator begin, vector<string>::iterator end, string& errors)
{
  auto lock = s_cookiestore.lock();
  uint64_t count = 0;
  while (begin != end) {
    try {
      CookieEntry entry;
      entry.d_address = ComboAddress(*begin, 53);
      entry.setSupport(CookieEntry::Support::Unsupported, std::numeric_limits<time_t>::max());
      auto [iter, inserted] = lock->insert(entry);
      if (!inserted) {
        lock->replace(iter, entry);
      }
      ++count;
    }
    catch (const PDNSException& error) {
      if (!errors.empty()) {
        errors += ", ";
      }
      errors += error.reason;
    }
    ++begin;
  }
  return count;
}

uint64_t clearCookies(vector<string>::iterator begin, vector<string>::iterator end, string& errors)
{
  auto lock = s_cookiestore.lock();
  uint64_t count = 0;
  if (begin == end) {
    return 0;
  }
  if (*begin == "*") {
    count = lock->size();
    lock->clear();
  }
  else {
    while (begin != end) {
      try {
        count += lock->erase(ComboAddress(*begin, 53));
      }
      catch (const PDNSException& error) {
        if (!errors.empty()) {
          errors += ", ";
        }
        errors += error.reason;
      }
      ++begin;
    }
  }
  return count;
}

void pruneCookies(time_t cutoff)
{
  auto lock = s_cookiestore.lock();
  lock->prune(cutoff);
}

uint64_t dumpCookies(int fileDesc)
{
  CookieStore copy;
  {
    auto lock = s_cookiestore.lock();
    copy = *lock;
  }
  return copy.dump(fileDesc);
}

void remoteLoggerQueueData(RemoteLoggerInterface& rli, const std::string& data)
{
  auto ret = rli.queueData(data);

  switch (ret) {
  case RemoteLoggerInterface::Result::Queued:
    break;
  case RemoteLoggerInterface::Result::PipeFull: {
    const auto& msg = RemoteLoggerInterface::toErrorString(ret);
    g_slog->withName(rli.name())->info(Logr::Debug, msg);
    break;
  }
  case RemoteLoggerInterface::Result::TooLarge: {
    const auto& msg = RemoteLoggerInterface::toErrorString(ret);
    g_slog->withName(rli.name())->info(Logr::Debug, msg);
    break;
  }
  case RemoteLoggerInterface::Result::OtherError: {
    const auto& msg = RemoteLoggerInterface::toErrorString(ret);
    g_slog->withName(rli.name())->info(Logr::Warning, msg);
    break;
  }
  }
}

#include "dnstap.hh"

#ifdef HAVE_FSTRM
#include "fstrm_logger.hh"

static bool isEnabledForQueries(const std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>& fstreamLoggers)
{
  if (fstreamLoggers == nullptr) {
    return false;
  }
  for (auto& logger : *fstreamLoggers) {
    if (logger->logQueries()) {
      return true;
    }
  }
  return false;
}

static void logFstreamQuery(const std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>& fstreamLoggers, const struct timeval& queryTime, const ComboAddress& localip, const ComboAddress& address, DnstapMessage::ProtocolType protocol, const boost::optional<const DNSName&>& auth, const vector<uint8_t>& packet)
{
  if (fstreamLoggers == nullptr)
    return;

  struct timespec ts;
  TIMEVAL_TO_TIMESPEC(&queryTime, &ts);
  std::string str;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DnstapMessage message(std::move(str), DnstapMessage::MessageType::resolver_query, SyncRes::s_serverID, &localip, &address, protocol, reinterpret_cast<const char*>(packet.data()), packet.size(), &ts, nullptr, auth);
  str = message.getBuffer();

  for (auto& logger : *fstreamLoggers) {
    remoteLoggerQueueData(*logger, str);
  }
}

static bool isEnabledForResponses(const std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>& fstreamLoggers)
{
  if (fstreamLoggers == nullptr) {
    return false;
  }
  for (auto& logger : *fstreamLoggers) {
    if (logger->logResponses()) {
      return true;
    }
  }
  return false;
}

static void logFstreamResponse(const std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>& fstreamLoggers, const ComboAddress& localip, const ComboAddress& address, DnstapMessage::ProtocolType protocol, const boost::optional<const DNSName&>& auth, const PacketBuffer& packet, const struct timeval& queryTime, const struct timeval& replyTime)
{
  if (fstreamLoggers == nullptr)
    return;

  struct timespec ts1, ts2;
  TIMEVAL_TO_TIMESPEC(&queryTime, &ts1);
  TIMEVAL_TO_TIMESPEC(&replyTime, &ts2);
  std::string str;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DnstapMessage message(std::move(str), DnstapMessage::MessageType::resolver_response, SyncRes::s_serverID, &localip, &address, protocol, reinterpret_cast<const char*>(packet.data()), packet.size(), &ts1, &ts2, auth);
  str = message.getBuffer();

  for (auto& logger : *fstreamLoggers) {
    remoteLoggerQueueData(*logger, str);
  }
}

#endif // HAVE_FSTRM

static void logOutgoingQuery(const std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>>& outgoingLoggers, const boost::optional<const boost::uuids::uuid&>& initialRequestId, const boost::uuids::uuid& uuid, const ComboAddress& address, const DNSName& domain, int type, uint16_t qid, bool doTCP, bool tls, size_t bytes, const boost::optional<Netmask>& srcmask, const std::string& nsName)
{
  if (!outgoingLoggers) {
    return;
  }

  bool log = false;
  for (auto& logger : *outgoingLoggers) {
    if (logger->logQueries()) {
      log = true;
      break;
    }
  }

  if (!log) {
    return;
  }

  static thread_local std::string buffer;
  buffer.clear();
  pdns::ProtoZero::Message m{buffer};
  m.setType(pdns::ProtoZero::Message::MessageType::DNSOutgoingQueryType);
  m.setMessageIdentity(uuid);
  m.setSocketFamily(address.sin4.sin_family);
  if (!doTCP) {
    m.setSocketProtocol(pdns::ProtoZero::Message::TransportProtocol::UDP);
  }
  else if (!tls) {
    m.setSocketProtocol(pdns::ProtoZero::Message::TransportProtocol::TCP);
  }
  else {
    m.setSocketProtocol(pdns::ProtoZero::Message::TransportProtocol::DoT);
  }

  m.setTo(address);
  m.setInBytes(bytes);
  m.setTime();
  m.setId(qid);
  m.setQuestion(domain, type, QClass::IN);
  m.setToPort(address.getPort());
  m.setServerIdentity(SyncRes::s_serverID);

  if (initialRequestId) {
    m.setInitialRequestID(*initialRequestId);
  }

  if (srcmask) {
    m.setEDNSSubnet(*srcmask, 128);
  }

  if (!nsName.empty()) {
    m.setMeta("nsName", {nsName}, {});
  }
  for (auto& logger : *outgoingLoggers) {
    if (logger->logQueries()) {
      remoteLoggerQueueData(*logger, buffer);
    }
  }
}

static void logIncomingResponse(const std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>>& outgoingLoggers, const boost::optional<const boost::uuids::uuid&>& initialRequestId, const boost::uuids::uuid& uuid, const ComboAddress& address, const DNSName& domain, int type, uint16_t qid, bool doTCP, bool tls, const boost::optional<Netmask>& srcmask, size_t bytes, int rcode, const std::vector<DNSRecord>& records, const struct timeval& queryTime, const std::set<uint16_t>& exportTypes, const std::string& nsName)
{
  if (!outgoingLoggers) {
    return;
  }

  bool log = false;
  for (auto& logger : *outgoingLoggers) {
    if (logger->logResponses()) {
      log = true;
      break;
    }
  }

  if (!log) {
    return;
  }

  static thread_local std::string buffer;
  buffer.clear();
  pdns::ProtoZero::RecMessage m{buffer};
  m.setType(pdns::ProtoZero::Message::MessageType::DNSIncomingResponseType);
  m.setMessageIdentity(uuid);
  m.setSocketFamily(address.sin4.sin_family);
  if (!doTCP) {
    m.setSocketProtocol(pdns::ProtoZero::Message::TransportProtocol::UDP);
  }
  else if (!tls) {
    m.setSocketProtocol(pdns::ProtoZero::Message::TransportProtocol::TCP);
  }
  else {
    m.setSocketProtocol(pdns::ProtoZero::Message::TransportProtocol::DoT);
  }
  m.setTo(address);
  m.setInBytes(bytes);
  m.setTime();
  m.setId(qid);
  m.setQuestion(domain, type, QClass::IN);
  m.setToPort(address.getPort());
  m.setServerIdentity(SyncRes::s_serverID);

  if (initialRequestId) {
    m.setInitialRequestID(*initialRequestId);
  }

  if (srcmask) {
    m.setEDNSSubnet(*srcmask, 128);
  }
  if (!nsName.empty()) {
    m.setMeta("nsName", {nsName}, {});
  }

  m.startResponse();
  m.setQueryTime(queryTime.tv_sec, queryTime.tv_usec);
  if (rcode == -1) {
    m.setNetworkErrorResponseCode();
  }
  else {
    m.setResponseCode(rcode);
  }

  for (const auto& record : records) {
    m.addRR(record, exportTypes, std::nullopt);
  }
  m.commitResponse();

  for (auto& logger : *outgoingLoggers) {
    if (logger->logResponses()) {
      remoteLoggerQueueData(*logger, buffer);
    }
  }
}

class BindError
{
};

static bool tcpconnect(const OptLog& log, const ComboAddress& remote, const std::optional<ComboAddress> localBind, TCPOutConnectionManager::Connection& connection, bool& dnsOverTLS, const std::string& nsName)
{
  dnsOverTLS = SyncRes::s_dot_to_port_853 && remote.getPort() == 853;

  connection = t_tcp_manager.get({remote, localBind});
  if (connection.d_handler) {
    return false;
  }

  const struct timeval timeout{
    g_networkTimeoutMsec / 1000, static_cast<suseconds_t>(g_networkTimeoutMsec) % 1000 * 1000};
  Socket sock(remote.sin4.sin_family, SOCK_STREAM);
  sock.setNonBlocking();
  setTCPNoDelay(sock.getHandle());
  // Bind to the same address the cookie is associated with (RFC 9018 section 3 last paragraph)
  ComboAddress localip = localBind ? *localBind : pdns::getQueryLocalAddress(remote.sin4.sin_family, 0);
  if (localBind) {
    VLOG(log, "Connecting TCP to " << remote.toString() << " with specific local address " << localip.toString() << endl);
  }
  else {
    VLOG(log, "Connecting TCP to " << remote.toString() << " with no specific local address" << endl);
  }

  try {
    sock.bind(localip);
  }
  catch (const NetworkError& e) {
    if (localBind) {
      throw BindError();
    }
    throw;
  }

  std::shared_ptr<TLSCtx> tlsCtx{nullptr};
  if (dnsOverTLS) {
    TLSContextParameters tlsParams;
    tlsParams.d_provider = "openssl";
    tlsParams.d_validateCertificates = false;
    // tlsParams.d_caStore
    tlsCtx = getTLSContext(tlsParams);
    if (tlsCtx == nullptr) {
      g_slogout->info(Logr::Error, "DoT requested but not available", "server", Logging::Loggable(remote));
      dnsOverTLS = false;
    }
  }
  connection.d_handler = std::make_shared<TCPIOHandler>(nsName, false, sock.releaseHandle(), timeout, tlsCtx);
  connection.d_local = localBind;
  // Returned state ignored
  // This can throw an exception, retry will need to happen at higher level
  connection.d_handler->tryConnect(SyncRes::s_tcp_fast_open_connect, remote);
  return true;
}

static LWResult::Result tcpsendrecv(const ComboAddress& ip, TCPOutConnectionManager::Connection& connection,
                                    ComboAddress& localip, const vector<uint8_t>& vpacket, size_t& len, PacketBuffer& buf)
{
  socklen_t slen = ip.getSocklen();
  uint16_t tlen = htons(vpacket.size());
  const char* lenP = reinterpret_cast<const char*>(&tlen);

  len = 0; // in case of error
  localip.sin4.sin_family = ip.sin4.sin_family;
  if (getsockname(connection.d_handler->getDescriptor(), reinterpret_cast<sockaddr*>(&localip), &slen) != 0) {
    return LWResult::Result::PermanentError;
  }

  PacketBuffer packet;
  packet.reserve(2 + vpacket.size());
  packet.insert(packet.end(), lenP, lenP + 2);
  packet.insert(packet.end(), vpacket.begin(), vpacket.end());

  LWResult::Result ret = asendtcp(packet, connection.d_handler);
  if (ret != LWResult::Result::Success) {
    return ret;
  }

  ret = arecvtcp(packet, 2, connection.d_handler, false);
  if (ret != LWResult::Result::Success) {
    return ret;
  }

  memcpy(&tlen, packet.data(), sizeof(tlen));
  len = ntohs(tlen); // switch to the 'len' shared with the rest of the calling function

  // XXX receive into buf directly?
  packet.resize(len);
  ret = arecvtcp(packet, len, connection.d_handler, false);
  if (ret != LWResult::Result::Success) {
    return ret;
  }
  buf.resize(len);
  memcpy(buf.data(), packet.data(), len);
  return LWResult::Result::Success;
}

static void addPadding(const DNSPacketWriter& pw, size_t bufsize, DNSPacketWriter::optvect_t& opts)
{
  const size_t currentSize = pw.getSizeWithOpts(opts);
  if (currentSize < (bufsize - 4)) {
    const size_t remaining = bufsize - (currentSize + 4);
    /* from rfc8647, "4.1.  Recommended Strategy: Block-Length Padding":
       Clients SHOULD pad queries to the closest multiple of 128 octets.
       Note we are in the client role here.
    */
    const size_t blockSize = 128;
    const size_t modulo = (currentSize + 4) % blockSize;
    size_t padSize = 0;
    if (modulo > 0) {
      padSize = std::min(blockSize - modulo, remaining);
    }
    opts.emplace_back(EDNSOptionCode::PADDING, makeEDNSPaddingOptString(padSize));
  }
}

static void outgoingCookie(const OptLog& log, const ComboAddress& address, const timeval& now, DNSPacketWriter::optvect_t& opts, std::optional<EDNSCookiesOpt>& cookieSentOut, std::optional<ComboAddress>& addressToBindTo)
{
  auto lock = s_cookiestore.lock();
  if (auto found = lock->find(address); found != lock->end()) {
    switch (found->getSupport()) {
    case CookieEntry::Support::Supported:
    case CookieEntry::Support::Probing:
      cookieSentOut = found->d_cookie;
      addressToBindTo = found->d_localaddress;
      opts.emplace_back(EDNSOptionCode::COOKIE, cookieSentOut->makeOptString());
      found->d_lastused = now.tv_sec;
      VLOG(log, "Sending stored cookie info to " << address.toString() << ": " << found->d_cookie.toDisplayString() << endl);
      break;
    case CookieEntry::Support::Unsupported:
      VLOG(log, "Server " << address.toString() << " does not support cookies" << endl);
      break;
    }
    return;
  }
  // Server not in table, it's either new or was purged
  CookieEntry entry;
  entry.d_address = address;
  entry.d_cookie.makeClientCookie();
  cookieSentOut = entry.d_cookie;
  entry.setSupport(CookieEntry::Support::Probing, now.tv_sec);
  lock->emplace(entry);
  opts.emplace_back(EDNSOptionCode::COOKIE, cookieSentOut->makeOptString());
  VLOG(log, "Sending new client cookie info to " << address.toString() << ": " << entry.d_cookie.toDisplayString() << endl);
}

static std::pair<bool, LWResult::Result> incomingCookie(const OptLog& log, const ComboAddress& address, const ComboAddress& localip, const timeval& now, const std::optional<EDNSCookiesOpt>& cookieSentOut, const EDNSOpts& edo, bool doTCP, LWResult& lwr, bool& cookieFoundInReply)
{
  auto lock = s_cookiestore.lock();
  auto found = lock->find(address);

  if (found == lock->end()) {
    // We received cookie (we might have sent one out) but the server is not in the table?
    // This is a case of cannot happen, unless rec_control clear-cookies was called
    VLOG(log, "Cookie from " << address.toString() << " not found back in table" << endl);
    lwr.d_rcode = RCode::FormErr;
    lwr.d_validpacket = false;
    return {true, LWResult::Result::Success}; // success - oddly enough
  }

  // We have stored cookie info, scan for COOKIE option in EDNS
  if (const auto opt = edo.getFirstOption(EDNSOptionCode::COOKIE); opt != edo.d_options.end()) {
    if (EDNSCookiesOpt received; received.makeFromString(opt->second)) {
      cookieFoundInReply = true;
      VLOG(log, "Received cookie info back from " << address.toString() << ": " << received.toDisplayString() << endl);
      if (received.getClient() == cookieSentOut->getClient()) {
        VLOG(log, "Client cookie from " << address.toString() << " matched! Storing with localAddress " << localip.toString() << endl);
        ++t_Counters.at(rec::Counter::cookieMatched);
        found->d_localaddress = localip;
        found->d_cookie = received;
        if (found->getSupport() == CookieEntry::Support::Probing) {
          ++t_Counters.at(rec::Counter::cookieProbeSupported);
        }
        found->setSupport(CookieEntry::Support::Supported, now.tv_sec);
        // check extended error code
        uint16_t ercode = edo.getCombinedERCode(lwr.d_rcode);
        if (ercode == ERCode::BADCOOKIE) {
          lwr.d_validpacket = true;
          ++t_Counters.at(rec::Counter::cookieRetry);
          VLOG(log, "Server " << localip.toString() << " returned BADCOOKIE " << endl);
          return {true, LWResult::Result::BadCookie}; // We did update the entry, retry should succeed
        }
      }
      else {
        if (!doTCP) {
          // Server responded with a wrong client cookie, fall back to TCP, RFC 7873 5.3
          VLOG(log, "Server " << localip.toString() << " responded with wrong client cookie, fall back to TCP" << endl);
          lwr.d_validpacket = true;
          ++t_Counters.at(rec::Counter::cookieMismatchedOverUDP);
          return {true, LWResult::Result::Spoofed};
        }
        // mismatched cookie when already doing TCP, ignore that
        VLOG(log, "Server " << localip.toString() << " responded with wrong client cookie over TCP, ignoring that" << endl);
        ++t_Counters.at(rec::Counter::cookieMismatchedOverTCP);
      }
    }
    else {
      VLOG(log, "Malformed cookie in reply from " << address.toString() << ", dropping as if was a timeout" << endl);
      // Do something special if we get malformed repeatedly? And/or consider current status?
      lwr.d_validpacket = false;
      ++t_Counters.at(rec::Counter::cookieMalformed);
      return {true, LWResult::Result::Timeout};
    }
  } // COOKIE option found

  // The cases where something special needs to be done have been handled above
  return {false, LWResult::Result::Success};
}

/** lwr is only filled out in case 1 was returned, and even when returning 1 for 'success', lwr might contain DNS errors
    Never throws!
 */
// NOLINTNEXTLINE(readability-function-cognitive-complexity): https://github.com/PowerDNS/pdns/issues/12791
static LWResult::Result asyncresolve(const OptLog& log, const ComboAddress& address, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, const ResolveContext& context, const std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>>& outgoingLoggers, [[maybe_unused]] const std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>& fstrmLoggers, const std::set<uint16_t>& exportTypes, LWResult* lwr, bool* chained, TCPOutConnectionManager::Connection& connection)
{
  size_t len;
  size_t bufsize = g_outgoingEDNSBufsize;
  PacketBuffer buf;
  buf.resize(bufsize);
  vector<uint8_t> vpacket;
  //  string mapped0x20=dns0x20(domain);
  uint16_t qid = dns_random_uint16();
  DNSPacketWriter pw(vpacket, domain, type);
  bool dnsOverTLS = SyncRes::s_dot_to_port_853 && address.getPort() == 853;
  std::string nsName;
  if (!context.d_nsName.empty()) {
    nsName = context.d_nsName.toStringNoDot();
  }

  pw.getHeader()->rd = sendRDQuery;
  pw.getHeader()->id = qid;
  /* RFC 6840 section 5.9:
   *  This document further specifies that validating resolvers SHOULD set
   *  the CD bit on every upstream query.  This is regardless of whether
   *  the CD bit was set on the incoming query [...]
   *
   * sendRDQuery is only true if the qname is part of a forward-zone-recurse (or
   * set in the forward-zone-file), so we use this as an indicator for it being
   * an "upstream query". To stay true to "dnssec=off means 3.X behaviour", we
   * only set +CD on forwarded query in any mode other than dnssec=off.
   */
  pw.getHeader()->cd = (sendRDQuery && g_dnssecmode != DNSSECMode::Off);

  std::optional<EDNSSubnetOpts> subnetOpts = std::nullopt;
  std::optional<ComboAddress> addressToBindTo;
  std::optional<EDNSCookiesOpt> cookieSentOut;

  if (EDNS0Level > 0) {
    DNSPacketWriter::optvect_t opts;
    if (srcmask) {
      subnetOpts = EDNSSubnetOpts{};
      subnetOpts->setSource(*srcmask);
      opts.emplace_back(EDNSOptionCode::ECS, subnetOpts->makeOptString());
    }

    if (g_cookies) {
      outgoingCookie(log, address, *now, opts, cookieSentOut, addressToBindTo);
    }

    if (dnsOverTLS && g_paddingOutgoing) {
      addPadding(pw, bufsize, opts);
    }

    pw.addOpt(g_outgoingEDNSBufsize, 0, g_dnssecmode == DNSSECMode::Off ? 0 : EDNSOpts::DNSSECOK, opts);
    pw.commit();
  }
  lwr->d_rcode = 0;
  lwr->d_haveEDNS = false;
  LWResult::Result ret;

  DTime dt;
  dt.set();
  *now = dt.getTimeval();

  boost::uuids::uuid uuid;
  const struct timeval queryTime = *now;

  if (outgoingLoggers) {
    uuid = getUniqueID();
    logOutgoingQuery(outgoingLoggers, context.d_initialRequestId, uuid, address, domain, type, qid, doTCP, dnsOverTLS, vpacket.size(), srcmask, nsName);
  }

  srcmask = boost::none; // this is also our return value, even if EDNS0Level == 0

  // We only store the localip if needed for fstrm logging or cookie support
  ComboAddress localip;
  bool fstrmQEnabled = false;
  bool fstrmREnabled = false;

#ifdef HAVE_FSTRM
  if (isEnabledForQueries(fstrmLoggers)) {
    fstrmQEnabled = true;
  }
  if (isEnabledForResponses(fstrmLoggers)) {
    fstrmREnabled = true;
  }
#endif

  if (!doTCP) {
    int queryfd;
    try {
      ret = asendto(vpacket.data(), vpacket.size(), 0, address, addressToBindTo, qid, domain, type, subnetOpts, &queryfd, *now);
    }
    catch (const PDNSException& e) {
      if (addressToBindTo) {
        // Cookie info already has been added to packet, so we must retry from a higher level: SyncRes::asyncresolveWrapper
        auto lock = s_cookiestore.lock();
        lock->erase(address);
        return LWResult::Result::BindError;
      }
      throw;
    }
    if (ret != LWResult::Result::Success) {
      return ret;
    }

    if (queryfd <= -1) {
      *chained = true;
    }

    if (!*chained) {
      if (cookieSentOut || fstrmQEnabled || fstrmREnabled) {
        localip.sin4.sin_family = address.sin4.sin_family;
        socklen_t slen = address.getSocklen();
        (void)getsockname(queryfd, reinterpret_cast<sockaddr*>(&localip), &slen); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast))
      }
#ifdef HAVE_FSTRM
      if (fstrmQEnabled) {
        logFstreamQuery(fstrmLoggers, queryTime, localip, address, DnstapMessage::ProtocolType::DoUDP, context.d_auth ? context.d_auth : boost::none, vpacket);
      }
#endif
    }

    // sleep until we see an answer to this, interface to mtasker
    ret = arecvfrom(buf, 0, address, len, qid, domain, type, queryfd, subnetOpts, *now);
  }
  else {
    bool isNew{};
    do {
      try {
        // If we get a new (not re-used) TCP connection that does not
        // work, we give up. For reused connections, we assume the
        // peer has closed it on error, so we retry. At some point we
        // *will* get a new connection, so this loop is not endless.
        isNew = true; // tcpconnect() might throw for new connections. In that case, we want to break the loop, scanbuild complains here, which is a false positive afaik
        isNew = tcpconnect(log, address, addressToBindTo, connection, dnsOverTLS, nsName);
        ret = tcpsendrecv(address, connection, localip, vpacket, len, buf);
#ifdef HAVE_FSTRM
        if (fstrmQEnabled) {
          logFstreamQuery(fstrmLoggers, queryTime, localip, address, !dnsOverTLS ? DnstapMessage::ProtocolType::DoTCP : DnstapMessage::ProtocolType::DoT, context.d_auth, vpacket);
        }
#endif /* HAVE_FSTRM */
        if (ret == LWResult::Result::Success) {
          break;
        }
        connection.d_handler->close();
      }
      catch (const BindError&) {
        // Cookie info already has been added to packet, so we must retry from a higher level
        auto lock = s_cookiestore.lock();
        lock->erase(address);
        return LWResult::Result::BindError;
      }
      catch (const NetworkError&) {
        ret = LWResult::Result::OSLimitError; // OS limits error
      }
      catch (const runtime_error&) {
        ret = LWResult::Result::OSLimitError; // OS limits error (PermanentError is transport related)
      }
    } while (!isNew);
  }

  lwr->d_usec = dt.udiff();
  *now = dt.getTimeval();

  if (ret != LWResult::Result::Success) { // includes 'timeout'
    if (outgoingLoggers) {
      logIncomingResponse(outgoingLoggers, context.d_initialRequestId, uuid, address, domain, type, qid, doTCP, dnsOverTLS, srcmask, 0, -1, {}, queryTime, exportTypes, nsName);
    }
    return ret;
  }

  if (*chained) {
    auto msec = lwr->d_usec / 1000;
    if (msec > g_networkTimeoutMsec * 2 / 3) {
      auto jitterMsec = dns_random(msec);
      if (jitterMsec > 0) {
        mthreadSleep(jitterMsec);
      }
    }
  }

  buf.resize(len);

#ifdef HAVE_FSTRM
  if (fstrmREnabled && (!*chained || doTCP)) {
    DnstapMessage::ProtocolType protocol = doTCP ? DnstapMessage::ProtocolType::DoTCP : DnstapMessage::ProtocolType::DoUDP;
    if (dnsOverTLS) {
      protocol = DnstapMessage::ProtocolType::DoT;
    }
    logFstreamResponse(fstrmLoggers, localip, address, protocol, context.d_auth, buf, queryTime, *now);
  }
#endif /* HAVE_FSTRM */

  lwr->d_records.clear();
  try {
    lwr->d_tcbit = 0;
    MOADNSParser mdp(false, reinterpret_cast<const char*>(buf.data()), buf.size());
    lwr->d_aabit = mdp.d_header.aa;
    lwr->d_tcbit = mdp.d_header.tc;
    lwr->d_rcode = mdp.d_header.rcode;

    if (mdp.d_header.rcode == RCode::FormErr && mdp.d_qname.empty() && mdp.d_qtype == 0 && mdp.d_qclass == 0) {
      if (outgoingLoggers) {
        logIncomingResponse(outgoingLoggers, context.d_initialRequestId, uuid, address, domain, type, qid, doTCP, dnsOverTLS, srcmask, len, lwr->d_rcode, lwr->d_records, queryTime, exportTypes, nsName);
      }
      lwr->d_validpacket = true;
      return LWResult::Result::Success; // this is "success", the error is set in lwr->d_rcode
    }

    if (domain != mdp.d_qname) {
      if (!mdp.d_qname.empty() && domain.toString().find((char)0) == string::npos /* ugly */) { // embedded nulls are too noisy, plus empty domains are too
        g_slogout->info(Logr::Notice, "Packet purporting to come from remote server contained wrong answer",
                        "server", Logging::Loggable(address),
                        "qname", Logging::Loggable(domain),
                        "onwire", Logging::Loggable(mdp.d_qname));
      }
      // unexpected count has already been done @ pdns_recursor.cc
      goto out;
    }

    lwr->d_records.reserve(mdp.d_answers.size());
    for (const auto& answer : mdp.d_answers) {
      lwr->d_records.push_back(answer);
    }

    bool cookieFoundInReply = false;
    if (EDNSOpts edo; EDNS0Level > 0 && getEDNSOpts(mdp, &edo)) {
      lwr->d_haveEDNS = true;

      // If we sent out ECS, we can also expect to see a return with or without ECS, the absent case
      // is not handled explicitly. If we do see a ECS in the reply, the source part *must* match
      // with what we sent out. See https://www.rfc-editor.org/rfc/rfc7871#section-7.3. and section
      // 11.2.
      // For ECS hardening mode, the case where we sent out an ECS but did not receive a matching
      // one is handled in arecvfrom().
      if (subnetOpts) {
        // THE RFC is not clear about the case of having multiple ECS options. We only look at the first.
        if (const auto opt = edo.getFirstOption(EDNSOptionCode::ECS); opt != edo.d_options.end()) {
          EDNSSubnetOpts reso;
          if (EDNSSubnetOpts::getFromString(opt->second, &reso)) {
            if (!doTCP && reso.getSource() != subnetOpts->getSource()) {
              g_slogout->info(Logr::Notice, "Incoming ECS does not match outgoing",
                              "server", Logging::Loggable(address),
                              "qname", Logging::Loggable(domain),
                              "outgoing", Logging::Loggable(subnetOpts->getSource()),
                              "incoming", Logging::Loggable(reso.getSource()));
              return LWResult::Result::Spoofed;
            }
            /* rfc7871 states that 0 "indicate[s] that the answer is suitable for all addresses in FAMILY",
               so we might want to still pass the information along to be able to differentiate between
               IPv4 and IPv6. Still I'm pretty sure it doesn't matter in real life, so let's not duplicate
               entries in our cache. */
            if (reso.getScopePrefixLength() != 0) {
              uint8_t bits = std::min(reso.getScopePrefixLength(), subnetOpts->getSourcePrefixLength());
              auto outgoingECSAddr = subnetOpts->getSource().getNetwork();
              outgoingECSAddr.truncate(bits);
              srcmask = Netmask(outgoingECSAddr, bits);
            }
          }
        }
      }
      if (g_cookies && !*chained) {
        auto [done, result] = incomingCookie(log, address, localip, *now, cookieSentOut, edo, doTCP, *lwr, cookieFoundInReply);
        if (done) {
          return result;
        }
      }
    }

    // Case: we sent out a cookie but did not get one back
    if (cookieSentOut && !cookieFoundInReply && !*chained) {
      ++t_Counters.at(rec::Counter::cookieNotInReply);
      auto lock = s_cookiestore.lock();
      auto found = lock->find(address);
      if (found != lock->end()) {
        switch (found->getSupport()) {
        case CookieEntry::Support::Probing:
          VLOG(log, "No cookie in reply from " << address.toString() << ", was probing, setting support to Unsupported" << endl);
          found->setSupport(CookieEntry::Support::Unsupported, now->tv_sec);
          ++t_Counters.at(rec::Counter::cookieProbeUnsupported);
          break;
        case CookieEntry::Support::Unsupported:
          // We could have detected the server does not support cookies in the meantime
          VLOG(log, "No cookie in reply from " << address.toString() << ", cookie state is Unsupported, fine" << endl);
          break;
        case CookieEntry::Support::Supported:
          // RFC says: ignore replies not containing any cookie info, equivalent to timeout
          VLOG(log, "No cookie in reply from " << address.toString() << ", cookie state is Supported, dropping packet as if it timed out)" << endl);
          return LWResult::Result::Timeout;
          break;
        }
      }
      else {
        VLOG(log, "No cookie in reply from " << address.toString() << ", cookie state is Unknown, dropping packet as if it timed out" << endl);
        return LWResult::Result::Timeout;
      }
    }

    if (outgoingLoggers) {
      logIncomingResponse(outgoingLoggers, context.d_initialRequestId, uuid, address, domain, type, qid, doTCP, dnsOverTLS, srcmask, len, lwr->d_rcode, lwr->d_records, queryTime, exportTypes, nsName);
    }

    lwr->d_validpacket = true;
    return LWResult::Result::Success;
  }
  catch (const std::exception& mde) {
    if (::arg().mustDo("log-common-errors")) {
      g_slogout->error(Logr::Notice, mde.what(), "Unable to parse packet from remote server", "server", Logging::Loggable(address),
                       "exception", Logging::Loggable("std::exception"));
    }

    lwr->d_rcode = RCode::FormErr;
    lwr->d_validpacket = false;
    t_Counters.at(rec::Counter::serverParseError)++;

    if (outgoingLoggers) {
      logIncomingResponse(outgoingLoggers, context.d_initialRequestId, uuid, address, domain, type, qid, doTCP, dnsOverTLS, srcmask, len, lwr->d_rcode, lwr->d_records, queryTime, exportTypes, nsName);
    }

    return LWResult::Result::Success; // success - oddly enough
  }
  catch (...) {
    g_slogout->info(Logr::Notice, "Unknown error parsing packet from remote server", "server", Logging::Loggable(address));
  }

  t_Counters.at(rec::Counter::serverParseError)++;

out:
  if (!lwr->d_rcode) {
    lwr->d_rcode = RCode::ServFail;
  }

  return LWResult::Result::PermanentError;
}

LWResult::Result asyncresolve(const OptLog& log, const ComboAddress& address, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, const ResolveContext& context, const std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>>& outgoingLoggers, const std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>& fstrmLoggers, const std::set<uint16_t>& exportTypes, LWResult* lwr, bool* chained)
{
  TCPOutConnectionManager::Connection connection;
  auto ret = asyncresolve(log, address, domain, type, doTCP, sendRDQuery, EDNS0Level, now, srcmask, context, outgoingLoggers, fstrmLoggers, exportTypes, lwr, chained, connection);

  if (doTCP) {
    if (connection.d_handler && lwr->d_validpacket) {
      t_tcp_manager.store(*now, std::make_pair(address, connection.d_local), std::move(connection));
    }
  }
  return ret;
}
