#include "config.h"
#include "doh.hh"

#ifdef HAVE_DNS_OVER_HTTPS
#define H2O_USE_EPOLL 1

#include <cerrno>
#include <iostream>
#include <thread>

#include <boost/algorithm/string.hpp>
#include <h2o.h>
//#include <h2o/http1.h>
#include <h2o/http2.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "base64.hh"
#include "dnsname.hh"
#undef CERT
#include "dnsdist.hh"
#include "dnsdist-tcp.hh"
#include "misc.hh"
#include "dns.hh"
#include "dolog.hh"
#include "dnsdist-concurrent-connections.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-proxy-protocol.hh"
#include "dnsdist-rules.hh"
#include "dnsdist-xpf.hh"
#include "libssl.hh"
#include "threadname.hh"

/* So, how does this work. We use h2o for our http2 and TLS needs.
   If the operator has configured multiple IP addresses to listen on,
   we launch multiple h2o listener threads. We can hook in to multiple
   URLs though on the same IP. There is no SNI yet (I think).

   h2o is event driven, so we get callbacks if a new DNS query arrived.
   When it does, we do some minimal parsing on it, and send it on to the
   dnsdist worker thread which we also launched.

   This dnsdist worker thread injects the query into the normal dnsdist flow
   (over a pipe). The response also goes back over a (different) pipe,
   where we pick it up and deliver it back to h2o.

   For coordination, we use the h2o socket multiplexer, which is sensitive to our
   pipe too.
*/

/* h2o notes.
   Paths and parameters etc just *happen* to be null-terminated in HTTP2.
   They are not in HTTP1. So you MUST use the length field!
*/

/* 'Intermediate' compatibility from https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28default.29 */
#define DOH_DEFAULT_CIPHERS "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS"

class DOHAcceptContext
{
public:
  DOHAcceptContext()
  {
    memset(&d_h2o_accept_ctx, 0, sizeof(d_h2o_accept_ctx));
    d_rotatingTicketsKey.clear();
  }
  DOHAcceptContext(const DOHAcceptContext&) = delete;
  DOHAcceptContext& operator=(const DOHAcceptContext&) = delete;

  h2o_accept_ctx_t* get()
  {
    return &d_h2o_accept_ctx;
  }

  ~DOHAcceptContext()
  {
    SSL_CTX_free(d_h2o_accept_ctx.ssl_ctx);
    d_h2o_accept_ctx.ssl_ctx = nullptr;
  }

  void decrementConcurrentConnections()
  {
    if (d_cs != nullptr) {
      --d_cs->tcpCurrentConnections;
    }
  }

  time_t getNextTicketsKeyRotation() const
  {
    return d_ticketsKeyNextRotation;
  }

  size_t getTicketsKeysCount() const
  {
    size_t res = 0;
    if (d_ticketKeys) {
      res = d_ticketKeys->getKeysCount();
    }
    return res;
  }

  void rotateTicketsKey(time_t now)
  {
    if (!d_ticketKeys) {
      return;
    }

    d_ticketKeys->rotateTicketsKey(now);

    if (d_ticketsKeyRotationDelay > 0) {
      d_ticketsKeyNextRotation = now + d_ticketsKeyRotationDelay;
    }
  }

  void loadTicketsKeys(const std::string& keyFile)
  {
    if (!d_ticketKeys) {
      return;
    }
    d_ticketKeys->loadTicketsKeys(keyFile);

    if (d_ticketsKeyRotationDelay > 0) {
      d_ticketsKeyNextRotation = time(nullptr) + d_ticketsKeyRotationDelay;
    }
  }

  void handleTicketsKeyRotation()
  {
    if (d_ticketsKeyRotationDelay == 0) {
      return;
    }

    time_t now = time(nullptr);
    if (now > d_ticketsKeyNextRotation) {
      if (d_rotatingTicketsKey.test_and_set()) {
        /* someone is already rotating */
        return;
      }
      try {
        rotateTicketsKey(now);

        d_rotatingTicketsKey.clear();
      }
      catch(const std::runtime_error& e) {
        d_rotatingTicketsKey.clear();
        throw std::runtime_error(std::string("Error generating a new tickets key for TLS context:") + e.what());
      }
      catch(...) {
        d_rotatingTicketsKey.clear();
        throw;
      }
    }
  }

  std::map<int, std::string> d_ocspResponses;
  std::unique_ptr<OpenSSLTLSTicketKeysRing> d_ticketKeys{nullptr};
  std::unique_ptr<FILE, int(*)(FILE*)> d_keyLogFile{nullptr, fclose};
  ClientState* d_cs{nullptr};
  time_t d_ticketsKeyRotationDelay{0};

private:
  h2o_accept_ctx_t d_h2o_accept_ctx;
  std::atomic<uint64_t> d_refcnt{1};
  time_t d_ticketsKeyNextRotation{0};
  std::atomic_flag d_rotatingTicketsKey;
};

// we create one of these per thread, and pass around a pointer to it
// through the bowels of h2o
struct DOHServerConfig
{
  DOHServerConfig(uint32_t idleTimeout, uint32_t internalPipeBufferSize): accept_ctx(std::make_shared<DOHAcceptContext>())
  {
    int fd[2];
#ifndef USE_SINGLE_ACCEPTOR_THREAD
    if (pipe(fd) < 0) {
      unixDie("Creating a pipe for DNS over HTTPS");
    }
    dohquerypair[0] = fd[1];
    dohquerypair[1] = fd[0];

    setNonBlocking(dohquerypair[0]);
    if (internalPipeBufferSize > 0) {
      setPipeBufferSize(dohquerypair[0], internalPipeBufferSize);
    }
#endif /* USE_SINGLE_ACCEPTOR_THREAD */

    if (pipe(fd) < 0) {
#ifndef USE_SINGLE_ACCEPTOR_THREAD
      close(dohquerypair[0]);
      close(dohquerypair[1]);
#endif /* USE_SINGLE_ACCEPTOR_THREAD */
      unixDie("Creating a pipe for DNS over HTTPS");
    }

    dohresponsepair[0] = fd[1];
    dohresponsepair[1] = fd[0];

    setNonBlocking(dohresponsepair[0]);
    if (internalPipeBufferSize > 0) {
      setPipeBufferSize(dohresponsepair[0], internalPipeBufferSize);
    }

    setNonBlocking(dohresponsepair[1]);

    h2o_config_init(&h2o_config);
    h2o_config.http2.idle_timeout = idleTimeout * 1000;
    /* if you came here for a way to make the number of concurrent streams (concurrent requests per connection)
       configurable, or even just bigger, I have bad news for you.
       h2o_config.http2.max_concurrent_requests_per_connection (default of 100) is capped by
       H2O_HTTP2_SETTINGS_HOST.max_concurrent_streams which is not configurable. Even if decided to change the
       hard-coded value, libh2o's author warns that there might be parts of the code where the stream ID is stored
       in 8 bits, making 256 a hard value: https://github.com/h2o/h2o/issues/805
    */
  }
  DOHServerConfig(const DOHServerConfig&) = delete;
  DOHServerConfig& operator=(const DOHServerConfig&) = delete;

  LocalHolders holders;
  std::set<std::string, std::less<>> paths;
  h2o_globalconf_t h2o_config;
  h2o_context_t h2o_ctx;
  std::shared_ptr<DOHAcceptContext> accept_ctx{nullptr};
  ClientState* cs{nullptr};
  std::shared_ptr<DOHFrontend> df{nullptr};
#ifndef USE_SINGLE_ACCEPTOR_THREAD
  int dohquerypair[2]{-1,-1};
#endif /* USE_SINGLE_ACCEPTOR_THREAD */
  int dohresponsepair[2]{-1,-1};
};

/* This internal function sends back the object to the main thread to send a reply.
   The caller should NOT release or touch the unit after calling this function */
static void sendDoHUnitToTheMainThread(DOHUnitUniquePtr&& du, const char* description)
{
  /* taking a naked pointer since we are about to send that pointer over a pipe */
  auto ptr = du.release();
  /* increasing the reference counter. This should not be strictly needed because
     we already hold a reference and will only release it if we failed to send the
     pointer over the pipe, but TSAN seems confused when the responder thread gets
     a reply from a backend before the send() syscall sending the corresponding query
     to that backend has returned in the initial thread.
     The memory barrier needed to increase that counter seems to work around that.
  */
  ptr->get();
  static_assert(sizeof(ptr) <= PIPE_BUF, "Writes up to PIPE_BUF are guaranteed not to be interleaved and to either fully succeed or fail");

  ssize_t sent = write(ptr->rsock, &ptr, sizeof(ptr));
  if (sent != sizeof(ptr)) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      ++g_stats.dohResponsePipeFull;
      vinfolog("Unable to pass a %s to the DoH worker thread because the pipe is full", description);
    }
    else {
      vinfolog("Unable to pass a %s to the DoH worker thread because we couldn't write to the pipe: %s", description, stringerror());
    }

    /* we fail to write over the pipe so we do not need to hold to that ref anymore */
    ptr->release();
  }
  /* we decrement the counter incremented above at the beginning of that function */
  ptr->release();
}

/* This function is called from other threads than the main DoH one,
   instructing it to send a 502 error to the client.
   It takes ownership of the unit. */
void handleDOHTimeout(DOHUnitUniquePtr&& oldDU)
{
  if (oldDU == nullptr) {
    return;
  }

  /* we are about to erase an existing DU */
  oldDU->status_code = 502;

  sendDoHUnitToTheMainThread(std::move(oldDU), "DoH timeout");
}

struct DOHConnection
{
  std::shared_ptr<DOHAcceptContext> d_acceptCtx{nullptr};
  ComboAddress d_remote;
  ComboAddress d_local;
  struct timeval d_connectionStartTime{0, 0};
  size_t d_nbQueries{0};
  int d_desc{-1};
};

static thread_local std::unordered_map<int, DOHConnection> t_conns;

static void on_socketclose(void *data)
{
  auto conn = reinterpret_cast<DOHConnection*>(data);
  if (conn != nullptr) {
    if (conn->d_acceptCtx) {
      struct timeval now;
      gettimeofday(&now, nullptr);

      auto diff = now - conn->d_connectionStartTime;

      conn->d_acceptCtx->decrementConcurrentConnections();
      conn->d_acceptCtx->d_cs->updateTCPMetrics(conn->d_nbQueries, diff.tv_sec * 1000 + diff.tv_usec / 1000);
    }

    dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(conn->d_remote);
    // you can no longer touch conn, or data, after this call
    t_conns.erase(conn->d_desc);
  }
}

static const std::string& getReasonFromStatusCode(uint16_t statusCode)
{
  /* no need to care too much about this, HTTP/2 has no 'reason' anyway */
  static const std::unordered_map<uint16_t, std::string> reasons = {
    { 200, "OK" },
    { 301, "Moved Permanently" },
    { 302, "Found" },
    { 303, "See Other" },
    { 304, "Not Modified" },
    { 305, "Use Proxy" },
    { 306, "Switch Proxy" },
    { 307, "Temporary Redirect" },
    { 308, "Permanent Redirect" },
    { 400, "Bad Request" },
    { 401, "Unauthorized" },
    { 402, "Payment Required" },
    { 403, "Forbidden" },
    { 404, "Not Found" },
    { 405, "Method Not Allowed" },
    { 406, "Not Acceptable" },
    { 407, "Proxy Authentication Required" },
    { 408, "Request Timeout" },
    { 409, "Conflict" },
    { 410, "Gone" },
    { 411, "Length Required" },
    { 412, "Precondition Failed" },
    { 413, "Payload Too Large" },
    { 414, "URI Too Long" },
    { 415, "Unsupported Media Type" },
    { 416, "Range Not Satisfiable" },
    { 417, "Expectation Failed" },
    { 418, "I'm a teapot" },
    { 451, "Unavailable For Legal Reasons" },
    { 500, "Internal Server Error" },
    { 501, "Not Implemented" },
    { 502, "Bad Gateway" },
    { 503, "Service Unavailable" },
    { 504, "Gateway Timeout" },
    { 505, "HTTP Version Not Supported" }
  };
  static const std::string unknown = "Unknown";

  const auto it = reasons.find(statusCode);
  if (it == reasons.end()) {
    return unknown;
  }
  else {
    return it->second;
  }
}

/* Always called from the main DoH thread */
static void handleResponse(DOHFrontend& df, st_h2o_req_t* req, uint16_t statusCode, const PacketBuffer& response, const std::unordered_map<std::string, std::string>& customResponseHeaders, const std::string& contentType, bool addContentType)
{
  constexpr int overwrite_if_exists = 1;
  constexpr int maybe_token = 1;
  for (auto const& headerPair : customResponseHeaders) {
    h2o_set_header_by_str(&req->pool, &req->res.headers, headerPair.first.c_str(), headerPair.first.size(), maybe_token, headerPair.second.c_str(), headerPair.second.size(), overwrite_if_exists);
  }

  if (statusCode == 200) {
    ++df.d_validresponses;
    req->res.status = 200;

    if (addContentType) {
      if (contentType.empty()) {
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, nullptr, H2O_STRLIT("application/dns-message"));
      }
      else {
        /* we need to duplicate the header content because h2o keeps a pointer and we will be deleted before the response has been sent */
        h2o_iovec_t ct = h2o_strdup(&req->pool, contentType.c_str(), contentType.size());
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, nullptr, ct.base, ct.len);
      }
    }

    if (df.d_sendCacheControlHeaders && response.size() > sizeof(dnsheader)) {
      uint32_t minTTL = getDNSPacketMinTTL(reinterpret_cast<const char*>(response.data()), response.size());
      if (minTTL != std::numeric_limits<uint32_t>::max()) {
        std::string cacheControlValue = "max-age=" + std::to_string(minTTL);
        /* we need to duplicate the header content because h2o keeps a pointer and we will be deleted before the response has been sent */
        h2o_iovec_t ccv = h2o_strdup(&req->pool, cacheControlValue.c_str(), cacheControlValue.size());
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CACHE_CONTROL, nullptr, ccv.base, ccv.len);
      }
    }

    req->res.content_length = response.size();
    h2o_send_inline(req, reinterpret_cast<const char*>(response.data()), response.size());
  }
  else if (statusCode >= 300 && statusCode < 400) {
    /* in that case the response is actually a URL */
    /* we need to duplicate the URL because h2o uses it for the location header, keeping a pointer, and we will be deleted before the response has been sent */
    h2o_iovec_t url = h2o_strdup(&req->pool, reinterpret_cast<const char*>(response.data()), response.size());
    h2o_send_redirect(req, statusCode, getReasonFromStatusCode(statusCode).c_str(), url.base, url.len);
    ++df.d_redirectresponses;
  }
  else {
    // we need to make sure it's null-terminated */
    if (!response.empty() && response.at(response.size() - 1) == 0) {
      h2o_send_error_generic(req, statusCode, getReasonFromStatusCode(statusCode).c_str(), reinterpret_cast<const char*>(response.data()), H2O_SEND_ERROR_KEEP_HEADERS);
    }
    else {
      switch(statusCode) {
      case 400:
        h2o_send_error_400(req, getReasonFromStatusCode(statusCode).c_str(), "invalid DNS query" , 0);
        break;
      case 403:
        h2o_send_error_403(req, getReasonFromStatusCode(statusCode).c_str(), "dns query not allowed", 0);
        break;
      case 502:
        h2o_send_error_502(req, getReasonFromStatusCode(statusCode).c_str(), "no downstream server available", 0);
        break;
      case 500:
        /* fall-through */
      default:
        h2o_send_error_500(req, getReasonFromStatusCode(statusCode).c_str(), "Internal Server Error", 0);
        break;
      }
    }

    ++df.d_errorresponses;
  }
}

class DoHTCPCrossQuerySender : public TCPQuerySender
{
public:
  DoHTCPCrossQuerySender()
  {
  }

  bool active() const override
  {
    return true;
  }

  void handleResponse(const struct timeval& now, TCPResponse&& response) override
  {
    if (!response.d_idstate.du) {
      return;
    }

    auto du = std::move(response.d_idstate.du);
    if (du->rsock == -1) {
      return;
    }

    du->response = std::move(response.d_buffer);
    du->ids = std::move(response.d_idstate);
    DNSResponse dr(du->ids, du->response, du->downstream);

    dnsheader cleartextDH;
    memcpy(&cleartextDH, dr.getHeader(), sizeof(cleartextDH));

    if (!response.isAsync()) {
      static thread_local LocalStateHolder<vector<DNSDistResponseRuleAction>> localRespRuleActions = g_respruleactions.getLocal();
      static thread_local LocalStateHolder<vector<DNSDistResponseRuleAction>> localCacheInsertedRespRuleActions = g_cacheInsertedRespRuleActions.getLocal();

      dr.ids.du = std::move(du);

      if (!processResponse(dr.ids.du->response, *localRespRuleActions, *localCacheInsertedRespRuleActions, dr, false)) {
        if (dr.ids.du) {
          dr.ids.du->status_code = 503;
          sendDoHUnitToTheMainThread(std::move(dr.ids.du), "Response dropped by rules");
        }
        return;
      }

      if (dr.isAsynchronous()) {
        return;
      }

      du = std::move(dr.ids.du);
    }

    if (!du->ids.selfGenerated) {
      double udiff = du->ids.queryRealTime.udiff();
      vinfolog("Got answer from %s, relayed to %s (https), took %f us", du->downstream->d_config.remote.toStringWithPort(), du->ids.origRemote.toStringWithPort(), udiff);

      auto backendProtocol = du->downstream->getProtocol();
      if (backendProtocol == dnsdist::Protocol::DoUDP && du->tcp) {
        backendProtocol = dnsdist::Protocol::DoTCP;
      }
      handleResponseSent(du->ids, udiff, du->ids.origRemote, du->downstream->d_config.remote, du->response.size(), cleartextDH, backendProtocol, true);
    }

    ++g_stats.responses;
    if (du->ids.cs) {
      ++du->ids.cs->responses;
    }

    sendDoHUnitToTheMainThread(std::move(du), "cross-protocol response");
  }

  void handleXFRResponse(const struct timeval& now, TCPResponse&& response) override
  {
    return handleResponse(now, std::move(response));
  }

  void notifyIOError(InternalQueryState&& query, const struct timeval& now) override
  {
    if (!query.du) {
      return;
    }

    if (query.du->rsock == -1) {
      return;
    }

    auto du = std::move(query.du);
    du->ids = std::move(query);
    du->status_code = 502;
    sendDoHUnitToTheMainThread(std::move(du), "cross-protocol error response");
  }
};

class DoHCrossProtocolQuery : public CrossProtocolQuery
{
public:
  DoHCrossProtocolQuery(DOHUnitUniquePtr&& du, bool isResponse)
  {
    if (isResponse) {
      /* happens when a response becomes async */
      query = InternalQuery(std::move(du->response), std::move(du->ids));
    }
    else {
      /* we need to duplicate the query here because we might need
         the existing query later if we get a truncated answer */
      query = InternalQuery(PacketBuffer(du->query), std::move(du->ids));
    }

    /* it might have been moved when we moved du->ids */
    if (du) {
      query.d_idstate.du = std::move(du);
    }

    /* we _could_ remove it from the query buffer and put in query's d_proxyProtocolPayload,
       clearing query.d_proxyProtocolPayloadAdded and du->proxyProtocolPayloadSize.
       Leave it for now because we know that the onky case where the payload has been
       added is when we tried over UDP, got a TC=1 answer and retried over TCP/DoT,
       and we know the TCP/DoT code can handle it. */
    query.d_proxyProtocolPayloadAdded = query.d_idstate.du->proxyProtocolPayloadSize > 0;
    downstream = query.d_idstate.du->downstream;
    proxyProtocolPayloadSize = query.d_idstate.du->proxyProtocolPayloadSize;
  }

  void handleInternalError()
  {
    query.d_idstate.du->status_code = 502;
    sendDoHUnitToTheMainThread(std::move(query.d_idstate.du), "DoH internal error");
  }

  std::shared_ptr<TCPQuerySender> getTCPQuerySender() override
  {
    query.d_idstate.du->downstream = downstream;
    return s_sender;
  }

  DNSQuestion getDQ() override
  {
    auto& ids = query.d_idstate;
    DNSQuestion dq(ids, query.d_buffer);
    return dq;
  }

  DNSResponse getDR() override
  {
    auto& ids = query.d_idstate;
    DNSResponse dr(ids, query.d_buffer, downstream);
    return dr;
   }

  DOHUnitUniquePtr&& releaseDU()
  {
    return std::move(query.d_idstate.du);
  }

private:
  static std::shared_ptr<DoHTCPCrossQuerySender> s_sender;
};

std::shared_ptr<DoHTCPCrossQuerySender> DoHCrossProtocolQuery::s_sender = std::make_shared<DoHTCPCrossQuerySender>();

std::unique_ptr<CrossProtocolQuery> getDoHCrossProtocolQueryFromDQ(DNSQuestion& dq, bool isResponse)
{
  if (!dq.ids.du) {
    throw std::runtime_error("Trying to create a DoH cross protocol query without a valid DoH unit");
  }

  auto du = std::move(dq.ids.du);
  if (&dq.ids != &du->ids) {
   du->ids = std::move(dq.ids);
  }

  du->ids.origID = dq.getHeader()->id;

  if (!isResponse) {
    if (du->query.data() != dq.getMutableData().data()) {
      du->query = std::move(dq.getMutableData());
    }
  }
  else {
    if (du->response.data() != dq.getMutableData().data()) {
      du->response = std::move(dq.getMutableData());
    }
  }

  return std::make_unique<DoHCrossProtocolQuery>(std::move(du), isResponse);
}

/*
   We are not in the main DoH thread but in the DoH 'client' thread.
*/
static void processDOHQuery(DOHUnitUniquePtr&& unit, bool inMainThread = false)
{
  const auto handleImmediateResponse = [inMainThread](DOHUnitUniquePtr&& du, const char* reason) {
    if (inMainThread) {
      handleResponse(*du->dsc->df, du->req, du->status_code, du->response, du->dsc->df->d_customResponseHeaders, du->contentType, true);
      /* so the unique pointer is stored in the InternalState which itself is stored in the unique pointer itself. We likely need
         a better design, but for now let's just reset the internal one since we know it is no longer needed. */
      du->ids.du.reset();
    }
    else {
      sendDoHUnitToTheMainThread(std::move(du), reason);
    }
  };

  auto& ids = unit->ids;
  ids.du = std::move(unit);
  auto& du = ids.du;
  uint16_t queryId = 0;
  ComboAddress remote;

  try {
    if (!du->req) {
      // we got closed meanwhile. XXX small race condition here
      // but we should be fine as long as we don't touch du->req
      // outside of the main DoH thread
      du->status_code = 500;
      handleImmediateResponse(std::move(du), "DoH killed in flight");
      return;
    }

    {
      // if there was no EDNS, we add it with a large buffer size
      // so we can use UDP to talk to the backend.
      auto dh = const_cast<struct dnsheader*>(reinterpret_cast<const struct dnsheader*>(du->query.data()));

      if (!dh->arcount) {
        if (generateOptRR(std::string(), du->query, 4096, 4096, 0, false)) {
          dh = const_cast<struct dnsheader*>(reinterpret_cast<const struct dnsheader*>(du->query.data())); // may have reallocated
          dh->arcount = htons(1);
          du->ids.ednsAdded = true;
        }
      }
      else {
        // we leave existing EDNS in place
      }
    }

    remote = du->ids.origRemote;
    DOHServerConfig* dsc = du->dsc;
    auto& holders = dsc->holders;
    ClientState& cs = *dsc->cs;

    if (du->query.size() < sizeof(dnsheader)) {
      ++g_stats.nonCompliantQueries;
      ++cs.nonCompliantQueries;
      du->status_code = 400;
      handleImmediateResponse(std::move(du), "DoH non-compliant query");
      return;
    }

    ++cs.queries;
    ++g_stats.queries;
    du->ids.queryRealTime.start();

    {
      /* don't keep that pointer around, it will be invalidated if the buffer is ever resized */
      struct dnsheader* dh = reinterpret_cast<struct dnsheader*>(du->query.data());

      if (!checkQueryHeaders(dh, cs)) {
        du->status_code = 400;
        handleImmediateResponse(std::move(du), "DoH invalid headers");
        return;
      }

      if (dh->qdcount == 0) {
        dh->rcode = RCode::NotImp;
        dh->qr = true;
        du->response = std::move(du->query);

        handleImmediateResponse(std::move(du), "DoH empty query");
        return;
      }

      queryId = ntohs(dh->id);
    }

    auto downstream = du->downstream;
    du->ids.qname = DNSName(reinterpret_cast<const char*>(du->query.data()), du->query.size(), sizeof(dnsheader), false, &du->ids.qtype, &du->ids.qclass);
    DNSQuestion dq(du->ids, du->query);
    const uint16_t* flags = getFlagsFromDNSHeader(dq.getHeader());
    ids.origFlags = *flags;
    du->ids.cs = &cs;
    dq.sni = std::move(du->sni);

    auto result = processQuery(dq, holders, downstream);

    if (result == ProcessQueryResult::Drop) {
      du->status_code = 403;
      handleImmediateResponse(std::move(du), "DoH dropped query");
      return;
    }
    else if (result == ProcessQueryResult::Asynchronous) {
      return;
    }
    else if (result == ProcessQueryResult::SendAnswer) {
      if (du->response.empty()) {
        du->response = std::move(du->query);
      }
      if (du->response.size() >= sizeof(dnsheader) && du->contentType.empty()) {
        auto dh = reinterpret_cast<const struct dnsheader*>(du->response.data());

        handleResponseSent(du->ids.qname, QType(du->ids.qtype), 0., du->ids.origDest, ComboAddress(), du->response.size(), *dh, dnsdist::Protocol::DoH, dnsdist::Protocol::DoH, false);
      }
      handleImmediateResponse(std::move(du), "DoH self-answered response");
      return;
    }

    if (result != ProcessQueryResult::PassToBackend) {
      du->status_code = 500;
      handleImmediateResponse(std::move(du), "DoH no backend available");
      return;
    }

    if (downstream == nullptr) {
      du->status_code = 502;
      handleImmediateResponse(std::move(du), "DoH no backend available");
      return;
    }

    du->downstream = downstream;

    if (downstream->isTCPOnly()) {
      std::string proxyProtocolPayload;
      /* we need to do this _before_ creating the cross protocol query because
         after that the buffer will have been moved */
      if (downstream->d_config.useProxyProtocol) {
        proxyProtocolPayload = getProxyProtocolPayload(dq);
      }

      du->ids.origID = htons(queryId);
      du->tcp = true;

      /* this moves du->ids, careful! */
      auto cpq = std::make_unique<DoHCrossProtocolQuery>(std::move(du), false);
      cpq->query.d_proxyProtocolPayload = std::move(proxyProtocolPayload);

      if (downstream->passCrossProtocolQuery(std::move(cpq))) {
        return;
      }
      else {
        if (inMainThread) {
          du = cpq->releaseDU();
          du->status_code = 502;
          handleImmediateResponse(std::move(du), "DoH internal error");
        }
        else {
          cpq->handleInternalError();
        }
        return;
      }
    }

    ComboAddress dest = dq.ids.origDest;
    if (!assignOutgoingUDPQueryToBackend(downstream, htons(queryId), dq, du->query, dest)) {
      du->status_code = 502;
      handleImmediateResponse(std::move(du), "DoH internal error");
      return;
    }
  }
  catch (const std::exception& e) {
    vinfolog("Got an error in DOH question thread while parsing a query from %s, id %d: %s", remote.toStringWithPort(), queryId, e.what());
    du->status_code = 500;
    handleImmediateResponse(std::move(du), "DoH internal error");
    return;
  }

  return;
}

/* called when a HTTP response is about to be sent, from the main DoH thread */
static void on_response_ready_cb(struct st_h2o_filter_t *self, h2o_req_t *req, h2o_ostream_t **slot)
{
  if (req == nullptr) {
    return;
  }

  DOHServerConfig* dsc = reinterpret_cast<DOHServerConfig*>(req->conn->ctx->storage.entries[0].data);

  DOHFrontend::HTTPVersionStats* stats = nullptr;
  if (req->version < 0x200) {
    /* HTTP 1.x */
    stats = &dsc->df->d_http1Stats;
  }
  else {
    /* HTTP 2.0 */
    stats = &dsc->df->d_http2Stats;
  }

  switch (req->res.status) {
  case 200:
    ++stats->d_nb200Responses;
    break;
  case 400:
    ++stats->d_nb400Responses;
    break;
  case 403:
    ++stats->d_nb403Responses;
    break;
  case 500:
    ++stats->d_nb500Responses;
    break;
  case 502:
    ++stats->d_nb502Responses;
    break;
  default:
    ++stats->d_nbOtherResponses;
    break;
  }

  h2o_setup_next_ostream(req, slot);
}

/* this is called by h2o when our request dies.
   We use this to signal to the 'du' that this req is no longer alive */
static void on_generator_dispose(void *_self)
{
  DOHUnit** du = reinterpret_cast<DOHUnit**>(_self);
  if (*du) { // if 0, on_dnsdist cleaned up du already
    (*du)->self = nullptr;
    (*du)->req = nullptr;
  }
}

/* This executes in the main DoH thread.
   We allocate a DOHUnit and send it to dnsdistclient() function in the doh client thread
   via a pipe */
static void doh_dispatch_query(DOHServerConfig* dsc, h2o_handler_t* self, h2o_req_t* req, PacketBuffer&& query, const ComboAddress& local, const ComboAddress& remote, std::string&& path)
{
  try {
    /* we only parse it there as a sanity check, we will parse it again later */
    DNSPacketMangler mangler(reinterpret_cast<char*>(query.data()), query.size());
    mangler.skipDomainName();
    mangler.skipBytes(4);

    /* we are doing quite some copies here, sorry about that,
       but we can't keep accessing the req object once we are in a different thread
       because the request might get killed by h2o at pretty much any time */
    auto du = std::make_unique<DOHUnit>(std::move(query), std::move(path), std::string(req->authority.base, req->authority.len));
    du->dsc = dsc;
    du->req = req;
    du->ids.origDest = local;
    du->ids.origRemote = remote;
    du->ids.protocol = dnsdist::Protocol::DoH;
    du->rsock = dsc->dohresponsepair[0];
    if (req->scheme != nullptr) {
      du->scheme = std::string(req->scheme->name.base, req->scheme->name.len);
    }
    du->query_at = req->query_at;

    if (dsc->df->d_keepIncomingHeaders) {
      du->headers = std::make_unique<std::unordered_map<std::string, std::string>>();
      du->headers->reserve(req->headers.size);
      for (size_t i = 0; i < req->headers.size; ++i) {
        (*du->headers)[std::string(req->headers.entries[i].name->base, req->headers.entries[i].name->len)] = std::string(req->headers.entries[i].value.base, req->headers.entries[i].value.len);
      }
    }

#ifdef HAVE_H2O_SOCKET_GET_SSL_SERVER_NAME
    h2o_socket_t* sock = req->conn->callbacks->get_socket(req->conn);
    const char * sni = h2o_socket_get_ssl_server_name(sock);
    if (sni != nullptr) {
      du->sni = sni;
    }
#endif /* HAVE_H2O_SOCKET_GET_SSL_SERVER_NAME */
    du->self = reinterpret_cast<DOHUnit**>(h2o_mem_alloc_shared(&req->pool, sizeof(*self), on_generator_dispose));
    auto ptr = du.release();
    *(ptr->self) = ptr;

#ifdef USE_SINGLE_ACCEPTOR_THREAD
    processDOHQuery(DOHUnitUniquePtr(ptr, DOHUnit::release), true);
#else /* USE_SINGLE_ACCEPTOR_THREAD */
    try  {
      static_assert(sizeof(ptr) <= PIPE_BUF, "Writes up to PIPE_BUF are guaranteed not to be interleaved and to either fully succeed or fail");
      ssize_t sent = write(dsc->dohquerypair[0], &ptr, sizeof(ptr));
      if (sent != sizeof(ptr)) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          ++g_stats.dohQueryPipeFull;
          vinfolog("Unable to pass a DoH query to the DoH worker thread because the pipe is full");
        }
        else {
          vinfolog("Unable to pass a DoH query to the DoH worker thread because we couldn't write to the pipe: %s", stringerror());
        }
        ptr->release();
        ptr = nullptr;
        h2o_send_error_500(req, "Internal Server Error", "Internal Server Error", 0);
      }
    }
    catch (...) {
      if (ptr != nullptr) {
        ptr->release();
      }
    }
#endif /* USE_SINGLE_ACCEPTOR_THREAD */
  }
  catch (const std::exception& e) {
    vinfolog("Had error parsing DoH DNS packet from %s: %s", remote.toStringWithPort(), e.what());
    h2o_send_error_400(req, "Bad Request", "The DNS query could not be parsed", 0);
  }
}

/* can only be called from the main DoH thread */
static bool getHTTPHeaderValue(const h2o_req_t* req, const std::string& headerName, std::string_view& value)
{
  bool found = false;
  /* early versions of boost::string_ref didn't have the ability to compare to string */
  std::string_view headerNameView(headerName);

  for (size_t i = 0; i < req->headers.size; ++i) {
    if (std::string_view(req->headers.entries[i].name->base, req->headers.entries[i].name->len) == headerNameView) {
      value = std::string_view(req->headers.entries[i].value.base, req->headers.entries[i].value.len);
      /* don't stop there, we might have more than one header with the same name, and we want the last one */
      found = true;
    }
  }

  return found;
}

/* can only be called from the main DoH thread */
static void processForwardedForHeader(const h2o_req_t* req, ComboAddress& remote)
{
  static const std::string headerName = "x-forwarded-for";
  std::string_view value;

  if (getHTTPHeaderValue(req, headerName, value)) {
    try {
      auto pos = value.rfind(',');
      if (pos != std::string_view::npos) {
        ++pos;
        for (; pos < value.size() && value[pos] == ' '; ++pos)
        {
        }

        if (pos < value.size()) {
          value = value.substr(pos);
        }
      }
      auto newRemote = ComboAddress(std::string(value));
      remote = newRemote;
    }
    catch (const std::exception& e) {
      vinfolog("Invalid X-Forwarded-For header ('%s') received from %s : %s", std::string(value), remote.toStringWithPort(), e.what());
    }
    catch (const PDNSException& e) {
      vinfolog("Invalid X-Forwarded-For header ('%s') received from %s : %s", std::string(value), remote.toStringWithPort(), e.reason);
    }
  }
}

/*
  A query has been parsed by h2o, this executes in the main DoH thread.
  For GET, the base64url-encoded payload is in the 'dns' parameter, which might be the first parameter, or not.
  For POST, the payload is the payload.
 */
static int doh_handler(h2o_handler_t *self, h2o_req_t *req)
{
  try {
    if (!req->conn->ctx->storage.size) {
      return 0; // although we might was well crash on this
    }
    DOHServerConfig* dsc = reinterpret_cast<DOHServerConfig*>(req->conn->ctx->storage.entries[0].data);
    h2o_socket_t* sock = req->conn->callbacks->get_socket(req->conn);

    const int descriptor = h2o_socket_get_fd(sock);
    if (descriptor == -1) {
      return 0;
    }

    auto& conn = t_conns.at(descriptor);
    ++conn.d_nbQueries;
    if (conn.d_nbQueries == 1) {
      if (h2o_socket_get_ssl_session_reused(sock) == 0) {
        ++dsc->cs->tlsNewSessions;
      }
      else {
        ++dsc->cs->tlsResumptions;
      }

      h2o_socket_getsockname(sock, reinterpret_cast<struct sockaddr*>(&conn.d_local));
    }

    if (dsc->df->d_trustForwardedForHeader) {
      processForwardedForHeader(req, conn.d_remote);
    }

    auto& holders = dsc->holders;
    if (!holders.acl->match(conn.d_remote)) {
      ++g_stats.aclDrops;
      vinfolog("Query from %s (DoH) dropped because of ACL", conn.d_remote.toStringWithPort());
      h2o_send_error_403(req, "Forbidden", "dns query not allowed because of ACL", 0);
      return 0;
    }

    if (auto tlsversion = h2o_socket_get_ssl_protocol_version(sock)) {
      if(!strcmp(tlsversion, "TLSv1.0"))
        ++dsc->cs->tls10queries;
      else if(!strcmp(tlsversion, "TLSv1.1"))
        ++dsc->cs->tls11queries;
      else if(!strcmp(tlsversion, "TLSv1.2"))
        ++dsc->cs->tls12queries;
      else if(!strcmp(tlsversion, "TLSv1.3"))
        ++dsc->cs->tls13queries;
      else
        ++dsc->cs->tlsUnknownqueries;
    }

    if (dsc->df->d_exactPathMatching) {
      const std::string_view pathOnly(req->path_normalized.base, req->path_normalized.len);
      if (dsc->paths.count(pathOnly) == 0) {
        h2o_send_error_404(req, "Not Found", "there is no endpoint configured for this path", 0);
        return 0;
      }
    }

    // would be nice to be able to use a std::string_view there,
    // but regex (called by matches() internally) requires a null-terminated string
    string path(req->path.base, req->path.len);
    /* the responses map can be updated at runtime, so we need to take a copy of
       the shared pointer, increasing the reference counter */
    auto responsesMap = dsc->df->d_responsesMap;
    /* 1 byte for the root label, 2 type, 2 class, 4 TTL (fake), 2 record length, 2 option length, 2 option code, 2 family, 1 source, 1 scope, 16 max for a full v6 */
    const size_t maxAdditionalSizeForEDNS = 35U;
    if (responsesMap) {
      for (const auto& entry : *responsesMap) {
        if (entry->matches(path)) {
          const auto& customHeaders = entry->getHeaders();
          handleResponse(*dsc->df, req, entry->getStatusCode(), entry->getContent(), customHeaders ? *customHeaders : dsc->df->d_customResponseHeaders, std::string(), false);
          return 0;
        }
      }
    }

    if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("POST"))) {
      ++dsc->df->d_postqueries;
      if(req->version >= 0x0200)
        ++dsc->df->d_http2Stats.d_nbQueries;
      else
        ++dsc->df->d_http1Stats.d_nbQueries;

      PacketBuffer query;
      /* We reserve a few additional bytes to be able to add EDNS later */
      query.reserve(req->entity.len + maxAdditionalSizeForEDNS);
      query.resize(req->entity.len);
      memcpy(query.data(), req->entity.base, req->entity.len);
      doh_dispatch_query(dsc, self, req, std::move(query), conn.d_local, conn.d_remote, std::move(path));
    }
    else if(req->query_at != SIZE_MAX && (req->path.len - req->query_at > 5)) {
      auto pos = path.find("?dns=");
      if(pos == string::npos)
        pos = path.find("&dns=");
      if(pos != string::npos) {
        // need to base64url decode this
        string sdns(path.substr(pos+5));
        boost::replace_all(sdns,"-", "+");
        boost::replace_all(sdns,"_", "/");
        // re-add padding that may have been missing
        switch (sdns.size() % 4) {
        case 2:
          sdns.append(2, '=');
          break;
        case 3:
          sdns.append(1, '=');
          break;
        }

        PacketBuffer decoded;

        /* rough estimate so we hopefully don't need a new allocation later */
        /* We reserve at few additional bytes to be able to add EDNS later */
        const size_t estimate = ((sdns.size() * 3) / 4);
        decoded.reserve(estimate + maxAdditionalSizeForEDNS);
        if(B64Decode(sdns, decoded) < 0) {
          h2o_send_error_400(req, "Bad Request", "Unable to decode BASE64-URL", 0);
          ++dsc->df->d_badrequests;
          return 0;
        }
        else {
          ++dsc->df->d_getqueries;
          if(req->version >= 0x0200)
            ++dsc->df->d_http2Stats.d_nbQueries;
          else
            ++dsc->df->d_http1Stats.d_nbQueries;

          doh_dispatch_query(dsc, self, req, std::move(decoded), conn.d_local, conn.d_remote, std::move(path));
        }
      }
      else
      {
        vinfolog("HTTP request without DNS parameter: %s", req->path.base);
        h2o_send_error_400(req, "Bad Request", "Unable to find the DNS parameter", 0);
        ++dsc->df->d_badrequests;
        return 0;
      }
    }
    else {
      h2o_send_error_400(req, "Bad Request", "Unable to parse the request", 0);
      ++dsc->df->d_badrequests;
    }
    return 0;
  }
  catch(const std::exception& e)
  {
    errlog("DOH Handler function failed with error %s", e.what());
    return 0;
  }
}

HTTPHeaderRule::HTTPHeaderRule(const std::string& header, const std::string& regex)
  : d_header(toLower(header)), d_regex(regex), d_visual("http[" + header+ "] ~ " + regex)
{
}

bool HTTPHeaderRule::matches(const DNSQuestion* dq) const
{
  if (!dq->ids.du || !dq->ids.du->headers) {
    return false;
  }

  for (const auto& header : *dq->ids.du->headers) {
    if (header.first == d_header) {
      return d_regex.match(header.second);
    }
  }
  return false;
}

string HTTPHeaderRule::toString() const
{
  return d_visual;
}

HTTPPathRule::HTTPPathRule(const std::string& path)
  :  d_path(path)
{

}

bool HTTPPathRule::matches(const DNSQuestion* dq) const
{
  if (!dq->ids.du) {
    return false;
  }

  if (dq->ids.du->query_at == SIZE_MAX) {
    return dq->ids.du->path == d_path;
  }
  else {
    return d_path.compare(0, d_path.size(), dq->ids.du->path, 0, dq->ids.du->query_at) == 0;
  }
}

string HTTPPathRule::toString() const
{
  return "url path == " + d_path;
}

HTTPPathRegexRule::HTTPPathRegexRule(const std::string& regex): d_regex(regex), d_visual("http path ~ " + regex)
{
}

bool HTTPPathRegexRule::matches(const DNSQuestion* dq) const
{
  if (!dq->ids.du) {
    return false;
  }

  return d_regex.match(dq->ids.du->getHTTPPath());
}

string HTTPPathRegexRule::toString() const
{
  return d_visual;
}

std::unordered_map<std::string, std::string> DOHUnit::getHTTPHeaders() const
{
  std::unordered_map<std::string, std::string> results;
  if (headers) {
    results.reserve(headers->size());

    for (const auto& header : *headers) {
      results.insert(header);
    }
  }

  return results;
}

std::string DOHUnit::getHTTPPath() const
{
  if (query_at == SIZE_MAX) {
    return path;
  }
  else {
    return std::string(path, 0, query_at);
  }
}

std::string DOHUnit::getHTTPHost() const
{
  return host;
}

std::string DOHUnit::getHTTPScheme() const
{
  return scheme;
}

std::string DOHUnit::getHTTPQueryString() const
{
  if (query_at == SIZE_MAX) {
    return std::string();
  }
  else {
    return path.substr(query_at);
  }
}

void DOHUnit::setHTTPResponse(uint16_t statusCode, PacketBuffer&& body_, const std::string& contentType_)
{
  status_code = statusCode;
  response = std::move(body_);
  if (!response.empty() && statusCode >= 400) {
    // we need to make sure it's null-terminated */
    if (response.at(response.size() - 1) != 0) {
      response.push_back(0);
    }
  }

  contentType = contentType_;
}

#ifndef USE_SINGLE_ACCEPTOR_THREAD
/* query has been parsed by h2o, which called doh_handler() in the main DoH thread.
   In order not to block for long, doh_handler() called doh_dispatch_query() which allocated
   a DOHUnit object and passed it to us */
static void dnsdistclient(int qsock)
{
  setThreadName("dnsdist/doh-cli");

  for(;;) {
    try {
      DOHUnit* ptr = nullptr;
      ssize_t got = read(qsock, &ptr, sizeof(ptr));
      if (got < 0) {
        warnlog("Error receiving internal DoH query: %s", strerror(errno));
        continue;
      }
      else if (static_cast<size_t>(got) < sizeof(ptr)) {
        continue;
      }

      DOHUnitUniquePtr du(ptr, DOHUnit::release);
      /* we are not in the main DoH thread anymore, so there is a real risk of
         a race condition where h2o kills the query while we are processing it,
         so we can't touch the content of du->req until we are back into the
         main DoH thread */
      if (!du->req) {
        // it got killed in flight already
        du->self = nullptr;
        continue;
      }

      processDOHQuery(std::move(du), false);
    }
    catch (const std::exception& e) {
      errlog("Error while processing query received over DoH: %s", e.what());
    }
    catch (...) {
      errlog("Unspecified error while processing query received over DoH");
    }
  }
}
#endif /* USE_SINGLE_ACCEPTOR_THREAD */

/* Called in the main DoH thread if h2o finds that dnsdist gave us an answer by writing into
   the dohresponsepair[0] side of the pipe so from:
   - handleDOHTimeout() when we did not get a response fast enough (called
     either from the health check thread (active) or from the frontend ones (reused))
   - dnsdistclient (error 500 because processDOHQuery() returned a negative value)
   - processDOHQuery (self-answered queries)
   */
static void on_dnsdist(h2o_socket_t *listener, const char *err)
{
  /* we want to read as many responses from the pipe as possible before
     giving up. Even if we are overloaded and fighting with the DoH connections
     for the CPU, the first thing we need to do is to send responses to free slots
     anyway, otherwise queries and responses are piling up in our pipes, consuming
     memory and likely coming up too late after the client has gone away */
  while (true) {
    DOHUnit *ptr = nullptr;
    DOHServerConfig* dsc = reinterpret_cast<DOHServerConfig*>(listener->data);
    ssize_t got = read(dsc->dohresponsepair[1], &ptr, sizeof(ptr));

    if (got < 0) {
      if (errno != EWOULDBLOCK && errno != EAGAIN) {
        errlog("Error reading a DOH internal response: %s", strerror(errno));
      }
      return;
    }
    else if (static_cast<size_t>(got) != sizeof(ptr)) {
      errlog("Error reading a DoH internal response, got %d bytes instead of the expected %d", got, sizeof(ptr));
      return;
    }

    DOHUnitUniquePtr du(ptr, DOHUnit::release);
    if (!du->req) { // it got killed in flight
      du->self = nullptr;
      continue;
    }

    if (!du->tcp &&
        du->truncated &&
        du->query.size() > du->proxyProtocolPayloadSize &&
        (du->query.size() - du->proxyProtocolPayloadSize) > sizeof(dnsheader)) {
      /* restoring the original ID */
      dnsheader* queryDH = reinterpret_cast<struct dnsheader*>(du->query.data() + du->proxyProtocolPayloadSize);
      queryDH->id = du->ids.origID;
      du->ids.forwardedOverUDP = false;
      du->tcp = true;
      du->truncated = false;
      du->response.clear();

      auto cpq = std::make_unique<DoHCrossProtocolQuery>(std::move(du), false);

      if (g_tcpclientthreads && g_tcpclientthreads->passCrossProtocolQueryToThread(std::move(cpq))) {
        continue;
      }
      else {
        vinfolog("Unable to pass DoH query to a TCP worker thread after getting a TC response over UDP");
        continue;
      }
    }

    if (du->self) {
      // we are back in the h2o main thread now, so we don't risk
      // a race (h2o killing the query) when accessing du->req anymore
      *du->self = nullptr; // so we don't clean up again in on_generator_dispose
      du->self = nullptr;
    }

    handleResponse(*dsc->df, du->req, du->status_code, du->response, dsc->df->d_customResponseHeaders, du->contentType, true);
  }
}

/* called when a TCP connection has been accepted, the TLS session has not been established */
static void on_accept(h2o_socket_t *listener, const char *err)
{
  DOHServerConfig* dsc = reinterpret_cast<DOHServerConfig*>(listener->data);
  h2o_socket_t *sock = nullptr;

  if (err != nullptr) {
    return;
  }

  if ((sock = h2o_evloop_socket_accept(listener)) == nullptr) {
    return;
  }

  const int descriptor = h2o_socket_get_fd(sock);
  if (descriptor == -1) {
    h2o_socket_close(sock);
    return;
  }

  ComboAddress remote;
  if (h2o_socket_getpeername(sock, reinterpret_cast<struct sockaddr*>(&remote)) == 0) {
    vinfolog("Dropping DoH connection because we could not retrieve the remote host");
    h2o_socket_close(sock);
    return;
  }

  if (!dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(remote)) {
    vinfolog("Dropping DoH connection from %s because we have too many from this client already", remote.toStringWithPort());
    h2o_socket_close(sock);
    return;
  }

  auto concurrentConnections = ++dsc->cs->tcpCurrentConnections;
  if (dsc->cs->d_tcpConcurrentConnectionsLimit > 0 && concurrentConnections > dsc->cs->d_tcpConcurrentConnectionsLimit) {
    --dsc->cs->tcpCurrentConnections;
    h2o_socket_close(sock);
    return;
  }

  if (concurrentConnections > dsc->cs->tcpMaxConcurrentConnections.load()) {
    dsc->cs->tcpMaxConcurrentConnections.store(concurrentConnections);
  }

  auto& conn = t_conns[descriptor];

  gettimeofday(&conn.d_connectionStartTime, nullptr);
  conn.d_nbQueries = 0;
  conn.d_acceptCtx = std::atomic_load_explicit(&dsc->accept_ctx, std::memory_order_acquire);
  conn.d_desc = descriptor;
  conn.d_remote = remote;

  sock->on_close.cb = on_socketclose;
  sock->on_close.data = &conn;
  sock->data = dsc;

  ++dsc->df->d_httpconnects;

  h2o_accept(conn.d_acceptCtx->get(), sock);
}

static int create_listener(std::shared_ptr<DOHServerConfig>& dsc, int fd)
{
  auto sock = h2o_evloop_socket_create(dsc->h2o_ctx.loop, fd, H2O_SOCKET_FLAG_DONT_READ);
  sock->data = dsc.get();
  h2o_socket_read_start(sock, on_accept);

  return 0;
}

#ifndef DISABLE_OCSP_STAPLING
static int ocsp_stapling_callback(SSL* ssl, void* arg)
{
  if (ssl == nullptr || arg == nullptr) {
    return SSL_TLSEXT_ERR_NOACK;
  }
  const auto ocspMap = reinterpret_cast<std::map<int, std::string>*>(arg);
  return libssl_ocsp_stapling_callback(ssl, *ocspMap);
}
#endif /* DISABLE_OCSP_STAPLING */

#if OPENSSL_VERSION_MAJOR >= 3
static int ticket_key_callback(SSL *s, unsigned char keyName[TLS_TICKETS_KEY_NAME_SIZE], unsigned char *iv, EVP_CIPHER_CTX *ectx, EVP_MAC_CTX *hctx, int enc)
#else
static int ticket_key_callback(SSL *s, unsigned char keyName[TLS_TICKETS_KEY_NAME_SIZE], unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc)
#endif
{
  DOHAcceptContext* ctx = reinterpret_cast<DOHAcceptContext*>(libssl_get_ticket_key_callback_data(s));
  if (ctx == nullptr || !ctx->d_ticketKeys) {
    return -1;
  }

  ctx->handleTicketsKeyRotation();

  auto ret = libssl_ticket_key_callback(s, *ctx->d_ticketKeys, keyName, iv, ectx, hctx, enc);
  if (enc == 0) {
    if (ret == 0) {
      ++ctx->d_cs->tlsUnknownTicketKey;
    }
    else if (ret == 2) {
      ++ctx->d_cs->tlsInactiveTicketKey;
    }
  }

  return ret;
}

static void setupTLSContext(DOHAcceptContext& acceptCtx,
                            TLSConfig& tlsConfig,
                            TLSErrorCounters& counters)
{
  if (tlsConfig.d_ciphers.empty()) {
    tlsConfig.d_ciphers = DOH_DEFAULT_CIPHERS;
  }

  auto [ctx, warnings] = libssl_init_server_context(tlsConfig, acceptCtx.d_ocspResponses);
  for (const auto& warning : warnings) {
    warnlog("%s", warning);
  }

  if (tlsConfig.d_enableTickets && tlsConfig.d_numberOfTicketsKeys > 0) {
    acceptCtx.d_ticketKeys = std::make_unique<OpenSSLTLSTicketKeysRing>(tlsConfig.d_numberOfTicketsKeys);
#if OPENSSL_VERSION_MAJOR >= 3
    SSL_CTX_set_tlsext_ticket_key_evp_cb(ctx.get(), &ticket_key_callback);
#else
    SSL_CTX_set_tlsext_ticket_key_cb(ctx.get(), &ticket_key_callback);
#endif
    libssl_set_ticket_key_callback_data(ctx.get(), &acceptCtx);
  }

#ifndef DISABLE_OCSP_STAPLING
  if (!acceptCtx.d_ocspResponses.empty()) {
    SSL_CTX_set_tlsext_status_cb(ctx.get(), &ocsp_stapling_callback);
    SSL_CTX_set_tlsext_status_arg(ctx.get(), &acceptCtx.d_ocspResponses);
  }
#endif /* DISABLE_OCSP_STAPLING */

  libssl_set_error_counters_callback(ctx, &counters);

  if (!tlsConfig.d_keyLogFile.empty()) {
    acceptCtx.d_keyLogFile = libssl_set_key_log_file(ctx, tlsConfig.d_keyLogFile);
  }

  h2o_ssl_register_alpn_protocols(ctx.get(), h2o_http2_alpn_protocols);

  acceptCtx.d_ticketsKeyRotationDelay = tlsConfig.d_ticketsKeyRotationDelay;
  if (tlsConfig.d_ticketKeyFile.empty()) {
    acceptCtx.handleTicketsKeyRotation();
  }
  else {
    acceptCtx.loadTicketsKeys(tlsConfig.d_ticketKeyFile);
  }

  auto nativeCtx = acceptCtx.get();
  nativeCtx->ssl_ctx = ctx.release();
}

static void setupAcceptContext(DOHAcceptContext& ctx, DOHServerConfig& dsc, bool setupTLS)
{
  auto nativeCtx = ctx.get();
  nativeCtx->ctx = &dsc.h2o_ctx;
  nativeCtx->hosts = dsc.h2o_config.hosts;
  ctx.d_ticketsKeyRotationDelay = dsc.df->d_tlsConfig.d_ticketsKeyRotationDelay;

  if (setupTLS && dsc.df->isHTTPS()) {
    try {
      setupTLSContext(ctx,
                      dsc.df->d_tlsConfig,
                      dsc.df->d_tlsCounters);
    }
    catch (const std::runtime_error& e) {
      throw std::runtime_error("Error setting up TLS context for DoH listener on '" + dsc.df->d_local.toStringWithPort() + "': " + e.what());
    }
  }
  ctx.d_cs = dsc.cs;
}

void DOHFrontend::rotateTicketsKey(time_t now)
{
  if (d_dsc && d_dsc->accept_ctx) {
    d_dsc->accept_ctx->rotateTicketsKey(now);
  }
}

void DOHFrontend::loadTicketsKeys(const std::string& keyFile)
{
  if (d_dsc && d_dsc->accept_ctx) {
    d_dsc->accept_ctx->loadTicketsKeys(keyFile);
  }
}

void DOHFrontend::handleTicketsKeyRotation()
{
  if (d_dsc && d_dsc->accept_ctx) {
    d_dsc->accept_ctx->handleTicketsKeyRotation();
  }
}

time_t DOHFrontend::getNextTicketsKeyRotation() const
{
  if (d_dsc && d_dsc->accept_ctx) {
    return d_dsc->accept_ctx->getNextTicketsKeyRotation();
  }
  return 0;
}

size_t DOHFrontend::getTicketsKeysCount() const
{
  size_t res = 0;
  if (d_dsc && d_dsc->accept_ctx) {
    res = d_dsc->accept_ctx->getTicketsKeysCount();
  }
  return res;
}

void DOHFrontend::reloadCertificates()
{
  auto newAcceptContext = std::make_shared<DOHAcceptContext>();
  setupAcceptContext(*newAcceptContext, *d_dsc, true);
  std::atomic_store_explicit(&d_dsc->accept_ctx, newAcceptContext, std::memory_order_release);
}

void DOHFrontend::setup()
{
  registerOpenSSLUser();

  d_dsc = std::make_shared<DOHServerConfig>(d_idleTimeout, d_internalPipeBufferSize);

  if  (isHTTPS()) {
    try {
      setupTLSContext(*d_dsc->accept_ctx,
                      d_tlsConfig,
                      d_tlsCounters);
    }
    catch (const std::runtime_error& e) {
      throw std::runtime_error("Error setting up TLS context for DoH listener on '" + d_local.toStringWithPort() + "': " + e.what());
    }
  }
}

static h2o_pathconf_t *register_handler(h2o_hostconf_t *hostconf, const char *path, int (*on_req)(h2o_handler_t *, h2o_req_t *))
{
  h2o_pathconf_t *pathconf = h2o_config_register_path(hostconf, path, 0);
  if (pathconf == nullptr) {
    return pathconf;
  }
  h2o_filter_t *filter = h2o_create_filter(pathconf, sizeof(*filter));
  if (filter) {
    filter->on_setup_ostream = on_response_ready_cb;
  }

  h2o_handler_t *handler = h2o_create_handler(pathconf, sizeof(*handler));
  if (handler != nullptr) {
    handler->on_req = on_req;
  }

  return pathconf;
}

// this is the entrypoint from dnsdist.cc
void dohThread(ClientState* cs)
{
  try {
    std::shared_ptr<DOHFrontend>& df = cs->dohFrontend;
    auto& dsc = df->d_dsc;
    dsc->cs = cs;
    dsc->df = cs->dohFrontend;
    dsc->h2o_config.server_name = h2o_iovec_init(df->d_serverTokens.c_str(), df->d_serverTokens.size());

#ifndef USE_SINGLE_ACCEPTOR_THREAD
    std::thread dnsdistThread(dnsdistclient, dsc->dohquerypair[1]);
    dnsdistThread.detach(); // gets us better error reporting
#endif

    setThreadName("dnsdist/doh");
    // I wonder if this registers an IP address.. I think it does
    // this may mean we need to actually register a site "name" here and not the IP address
    h2o_hostconf_t *hostconf = h2o_config_register_host(&dsc->h2o_config, h2o_iovec_init(df->d_local.toString().c_str(), df->d_local.toString().size()), 65535);

    for(const auto& url : df->d_urls) {
      register_handler(hostconf, url.c_str(), doh_handler);
      dsc->paths.insert(url);
    }

    h2o_context_init(&dsc->h2o_ctx, h2o_evloop_create(), &dsc->h2o_config);

    // in this complicated way we insert the DOHServerConfig pointer in there
    h2o_vector_reserve(nullptr, &dsc->h2o_ctx.storage, 1);
    dsc->h2o_ctx.storage.entries[0].data = dsc.get();
    ++dsc->h2o_ctx.storage.size;

    auto sock = h2o_evloop_socket_create(dsc->h2o_ctx.loop, dsc->dohresponsepair[1], H2O_SOCKET_FLAG_DONT_READ);
    sock->data = dsc.get();

    // this listens to responses from dnsdist to turn into http responses
    h2o_socket_read_start(sock, on_dnsdist);

    setupAcceptContext(*dsc->accept_ctx, *dsc, false);

    if (create_listener(dsc, cs->tcpFD) != 0) {
      throw std::runtime_error("DOH server failed to listen on " + df->d_local.toStringWithPort() + ": " + strerror(errno));
    }
    for (const auto& [addr, fd] : cs->d_additionalAddresses) {
      if (create_listener(dsc, fd) != 0) {
        throw std::runtime_error("DOH server failed to listen on additional address " + addr.toStringWithPort() + " for DOH local" + df->d_local.toStringWithPort() + ": " + strerror(errno));
      }
    }

    bool stop = false;
    do {
      int result = h2o_evloop_run(dsc->h2o_ctx.loop, INT32_MAX);
      if (result == -1) {
        if (errno != EINTR) {
          errlog("Error in the DoH event loop: %s", strerror(errno));
          stop = true;
        }
      }
    }
    while (stop == false);

  }
  catch (const std::exception& e) {
    throw runtime_error("DOH thread failed to launch: " + std::string(e.what()));
  }
  catch (...) {
    throw runtime_error("DOH thread failed to launch");
  }
}

void handleUDPResponseForDoH(DOHUnitUniquePtr&& du, PacketBuffer&& udpResponse, InternalQueryState&& state)
{
  du->response = std::move(udpResponse);
  du->ids = std::move(state);

  const dnsheader* dh = reinterpret_cast<const struct dnsheader*>(du->response.data());
  if (!dh->tc) {
    static thread_local LocalStateHolder<vector<DNSDistResponseRuleAction>> localRespRuleActions = g_respruleactions.getLocal();
    static thread_local LocalStateHolder<vector<DNSDistResponseRuleAction>> localCacheInsertedRespRuleActions = g_cacheInsertedRespRuleActions.getLocal();

    DNSResponse dr(du->ids, du->response, du->downstream);
    dnsheader cleartextDH;
    memcpy(&cleartextDH, dr.getHeader(), sizeof(cleartextDH));

    dr.ids.du = std::move(du);
    if (!processResponse(dr.ids.du->response, *localRespRuleActions, *localCacheInsertedRespRuleActions, dr, false)) {
      if (dr.ids.du) {
        dr.ids.du->status_code = 503;
        sendDoHUnitToTheMainThread(std::move(dr.ids.du), "Response dropped by rules");
      }
      return;
    }

    if (dr.isAsynchronous()) {
      return;
    }

    du = std::move(dr.ids.du);
    double udiff = du->ids.queryRealTime.udiff();
    vinfolog("Got answer from %s, relayed to %s (https), took %f us", du->downstream->d_config.remote.toStringWithPort(), du->ids.origRemote.toStringWithPort(), udiff);

    handleResponseSent(du->ids, udiff, dr.ids.origRemote, du->downstream->d_config.remote, du->response.size(), cleartextDH, du->downstream->getProtocol(), true);

    ++g_stats.responses;
    if (du->ids.cs) {
      ++du->ids.cs->responses;
    }
  }
  else {
    du->truncated = true;
  }

  sendDoHUnitToTheMainThread(std::move(du), "DoH response");
}

#else /* HAVE_DNS_OVER_HTTPS */

void handleDOHTimeout(DOHUnitUniquePtr&& oldDU)
{
}

#endif /* HAVE_DNS_OVER_HTTPS */
