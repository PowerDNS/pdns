#include "config.h"
#include "doh.hh"

#ifdef HAVE_DNS_OVER_HTTPS
#define H2O_USE_EPOLL 1

#include <errno.h>
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
#include "misc.hh"
#include "dns.hh"
#include "dolog.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-proxy-protocol.hh"
#include "dnsdist-rules.hh"
#include "dnsdist-xpf.hh"
#include "libssl.hh"
#include "threadname.hh"
#include "views.hh"

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
    ++d_refcnt;
    return &d_h2o_accept_ctx;
  }

  void release()
  {
    if (--d_refcnt == 0) {
      SSL_CTX_free(d_h2o_accept_ctx.ssl_ctx);
      d_h2o_accept_ctx.ssl_ctx = nullptr;
      delete this;
    }
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
  DOHServerConfig(uint32_t idleTimeout, uint32_t internalPipeBufferSize): accept_ctx(new DOHAcceptContext)
  {
    int fd[2];
    if (pipe(fd) < 0) {
      unixDie("Creating a pipe for DNS over HTTPS");
    }
    dohquerypair[0] = fd[1];
    dohquerypair[1] = fd[0];

    if (pipe(fd) < 0) {
      close(dohquerypair[0]);
      close(dohquerypair[1]);
      unixDie("Creating a pipe for DNS over HTTPS");
    }

    dohresponsepair[0] = fd[1];
    dohresponsepair[1] = fd[0];

    setNonBlocking(dohquerypair[0]);
    if (internalPipeBufferSize > 0) {
      setPipeBufferSize(dohquerypair[0], internalPipeBufferSize);
    }

    setNonBlocking(dohresponsepair[0]);
    if (internalPipeBufferSize > 0) {
      setPipeBufferSize(dohresponsepair[0], internalPipeBufferSize);
    }

    setNonBlocking(dohresponsepair[1]);

    h2o_config_init(&h2o_config);
    h2o_config.http2.idle_timeout = idleTimeout * 1000;
  }
  DOHServerConfig(const DOHServerConfig&) = delete;
  DOHServerConfig& operator=(const DOHServerConfig&) = delete;

  ~DOHServerConfig()
  {
    if (accept_ctx) {
      accept_ctx->release();
    }
  }

  LocalHolders holders;
  std::unordered_set<std::string> paths;
  h2o_globalconf_t h2o_config;
  h2o_context_t h2o_ctx;
  DOHAcceptContext* accept_ctx{nullptr};
  ClientState* cs{nullptr};
  std::shared_ptr<DOHFrontend> df{nullptr};
  int dohquerypair[2]{-1,-1};
  int dohresponsepair[2]{-1,-1};
};

/* This function is called from other threads than the main DoH one,
   instructing it to send a 502 error to the client */
void handleDOHTimeout(DOHUnit* oldDU)
{
  if (oldDU == nullptr) {
    return;
  }

/* we are about to erase an existing DU */
  oldDU->status_code = 502;

  /* increase the ref counter before sending the pointer */
  oldDU->get();

  static_assert(sizeof(oldDU) <= PIPE_BUF, "Writes up to PIPE_BUF are guaranteed not to be interleaved and to either fully succeed or fail");
  ssize_t sent = write(oldDU->rsock, &oldDU, sizeof(oldDU));
  if (sent != sizeof(oldDU)) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      ++g_stats.dohResponsePipeFull;
      vinfolog("Unable to pass a DoH timeout to the DoH worker thread because the pipe is full");
    }
    else {
      vinfolog("Unable to pass a DoH timeout to the DoH worker thread because we couldn't write to the pipe: %s", stringerror());
    }

    oldDU->release();
  }

  oldDU->release();
  oldDU = nullptr;
}

static void on_socketclose(void *data)
{
  DOHAcceptContext* ctx = reinterpret_cast<DOHAcceptContext*>(data);
  ctx->decrementConcurrentConnections();
  ctx->release();
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
static void handleResponse(DOHFrontend& df, st_h2o_req_t* req, uint16_t statusCode, const std::string& response, const std::vector<std::pair<std::string, std::string>>& customResponseHeaders, const std::string& contentType, bool addContentType)
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

    if (df.d_sendCacheControlHeaders && !response.empty()) {
      uint32_t minTTL = getDNSPacketMinTTL(response.data(), response.size());
      if (minTTL != std::numeric_limits<uint32_t>::max()) {
        std::string cacheControlValue = "max-age=" + std::to_string(minTTL);
        /* we need to duplicate the header content because h2o keeps a pointer and we will be deleted before the response has been sent */
        h2o_iovec_t ccv = h2o_strdup(&req->pool, cacheControlValue.c_str(), cacheControlValue.size());
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CACHE_CONTROL, nullptr, ccv.base, ccv.len);
      }
    }

    req->res.content_length = response.size();
    h2o_send_inline(req, response.c_str(), response.size());
  }
  else if (statusCode >= 300 && statusCode < 400) {
    /* in that case the response is actually a URL */
    /* we need to duplicate the URL because h2o uses it for the location header, keeping a pointer, and we will be deleted before the response has been sent */
    h2o_iovec_t url = h2o_strdup(&req->pool, response.c_str(), response.size());
    h2o_send_redirect(req, statusCode, getReasonFromStatusCode(statusCode).c_str(), url.base, url.len);
    ++df.d_redirectresponses;
  }
  else {
    if (!response.empty()) {
      h2o_send_error_generic(req, statusCode, getReasonFromStatusCode(statusCode).c_str(), response.c_str(), H2O_SEND_ERROR_KEEP_HEADERS);
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

/*
   this function calls 'return -1' to drop a query without sending it
   caller should make sure HTTPS thread hears of that
   We are not in the main DoH thread but in the DoH 'client' thread.
*/
static int processDOHQuery(DOHUnit* du)
{
  uint16_t queryId = 0;
  ComboAddress remote;
  bool duRefCountIncremented = false;
  try {
    if (!du->req) {
      // we got closed meanwhile. XXX small race condition here
      // but we should be fine as long as we don't touch du->req
      // outside of the main DoH thread
      return -1;
    }
    remote = du->remote;
    DOHServerConfig* dsc = du->dsc;
    auto& holders = dsc->holders;
    ClientState& cs = *dsc->cs;

    if (du->query.size() < sizeof(dnsheader)) {
      ++g_stats.nonCompliantQueries;
      du->status_code = 400;
      return -1;
    }

    ++cs.queries;
    ++g_stats.queries;

    /* we need an accurate ("real") value for the response and
       to store into the IDS, but not for insertion into the
       rings for example */
    struct timespec queryRealTime;
    gettime(&queryRealTime, true);
    uint16_t len = du->query.length();
    /* We reserve at least 512 additional bytes to be able to add EDNS, but we also want
       at least s_maxPacketCacheEntrySize bytes to be able to spoof the content or fill the answer from the packet cache */
    du->query.resize(std::max(du->query.size() + 512, s_maxPacketCacheEntrySize));
    size_t bufferSize = du->query.size();
    auto query = const_cast<char*>(du->query.c_str());
    struct dnsheader* dh = reinterpret_cast<struct dnsheader*>(query);

    if (!checkQueryHeaders(dh)) {
      du->status_code = 400;
      return -1; // drop
    }

    uint16_t qtype, qclass;
    unsigned int consumed = 0;
    DNSName qname(query, len, sizeof(dnsheader), false, &qtype, &qclass, &consumed);
    DNSQuestion dq(&qname, qtype, qclass, consumed, &du->dest, &du->remote, dh, bufferSize, len, false, &queryRealTime);
    dq.ednsAdded = du->ednsAdded;
    dq.du = du;
    queryId = ntohs(dh->id);
    dq.sni = std::move(du->sni);

    std::shared_ptr<DownstreamState> ss{nullptr};
    auto result = processQuery(dq, cs, holders, ss);

    if (result == ProcessQueryResult::Drop) {
      du->status_code = 403;
      return -1;
    }

    if (result == ProcessQueryResult::SendAnswer) {
      if (du->response.empty()) {
        du->response = std::string(reinterpret_cast<char*>(dq.dh), dq.len);
      }
      /* increase the ref counter before sending the pointer */
      du->get();

      static_assert(sizeof(du) <= PIPE_BUF, "Writes up to PIPE_BUF are guaranteed not to be interleaved and to either fully succeed or fail");
      ssize_t sent = write(du->rsock, &du, sizeof(du));
      if (sent != sizeof(du)) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          ++g_stats.dohResponsePipeFull;
          vinfolog("Unable to pass a DoH self-answered response to the DoH worker thread because the pipe is full");
        }
        else {
          vinfolog("Unable to pass a DoH self-answered to the DoH worker thread because we couldn't write to the pipe: %s", stringerror());
        }

        du->release();
      }
      return 0;
    }

    if (result != ProcessQueryResult::PassToBackend) {
      du->status_code = 500;
      return -1;
    }

    if (ss == nullptr) {
      du->status_code = 502;
      return -1;
    }

    ComboAddress dest = du->dest;
    unsigned int idOffset = (ss->idOffset++) % ss->idStates.size();
    IDState* ids = &ss->idStates[idOffset];
    ids->age = 0;
    DOHUnit* oldDU = nullptr;
    if (ids->isInUse()) {
      /* that means that the state was in use, possibly with an allocated
         DOHUnit that we will need to handle, but we can't touch it before
         confirming that we now own this state */
      oldDU = ids->du;
    }

    /* we atomically replace the value, we now own this state */
    int64_t generation = ids->generation++;
    if (!ids->markAsUsed(generation)) {
      /* the state was not in use.
         we reset 'oldDU' because it might have still been in use when we read it. */
      oldDU = nullptr;
      ++ss->outstanding;
    }
    else {
      ids->du = nullptr;
      /* we are reusing a state, no change in outstanding but if there was an existing DOHUnit we need
         to handle it because it's about to be overwritten. */
      ++ss->reuseds;
      ++g_stats.downstreamTimeouts;
      handleDOHTimeout(oldDU);
    }

    ids->origFD = 0;
    /* increase the ref count since we are about to store the pointer */
    du->get();
    duRefCountIncremented = true;
    ids->du = du;

    ids->cs = &cs;
    ids->origID = dh->id;
    setIDStateFromDNSQuestion(*ids, dq, std::move(qname));

    /* If we couldn't harvest the real dest addr, still
       write down the listening addr since it will be useful
       (especially if it's not an 'any' one).
       We need to keep track of which one it is since we may
       want to use the real but not the listening addr to reply.
    */
    if (dest.sin4.sin_family != 0) {
      ids->origDest = dest;
      ids->destHarvested = true;
    }
    else {
      ids->origDest = cs.local;
      ids->destHarvested = false;
    }

    dh->id = idOffset;

    if (ss->useProxyProtocol) {
      addProxyProtocol(dq);
    }

    int fd = pickBackendSocketForSending(ss);
    try {
      /* you can't touch du after this line, because it might already have been freed */
      ssize_t ret = udpClientSendRequestToBackend(ss, fd, query, dq.len);

      if(ret < 0) {
        /* we are about to handle the error, make sure that
           this pointer is not accessed when the state is cleaned,
           but first check that it still belongs to us */
        if (ids->tryMarkUnused(generation)) {
          ids->du = nullptr;
          du->release();
          duRefCountIncremented = false;
          --ss->outstanding;
        }
        ++ss->sendErrors;
        ++g_stats.downstreamSendErrors;
        du->status_code = 502;
        return -1;
      }
    }
    catch (const std::exception& e) {
      if (duRefCountIncremented) {
        du->release();
      }
      throw;
    }

    vinfolog("Got query for %s|%s from %s (https), relayed to %s", ids->qname.toString(), QType(ids->qtype).getName(), remote.toStringWithPort(), ss->getName());
  }
  catch(const std::exception& e) {
    vinfolog("Got an error in DOH question thread while parsing a query from %s, id %d: %s", remote.toStringWithPort(), queryId, e.what());
    du->status_code = 500;
    return -1;
  }

  return 0;
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
static void doh_dispatch_query(DOHServerConfig* dsc, h2o_handler_t* self, h2o_req_t* req, std::string&& query, const ComboAddress& local, const ComboAddress& remote, std::string&& path)
{
  try {
    /* we only parse it there as a sanity check, we will parse it again later */
    uint16_t qtype;
    DNSName qname(query.c_str(), query.size(), sizeof(dnsheader), false, &qtype);

    auto du = std::unique_ptr<DOHUnit>(new DOHUnit);
    du->dsc = dsc;
    du->req = req;
    du->dest = local;
    du->remote = remote;
    du->rsock = dsc->dohresponsepair[0];
    du->query = std::move(query);
    du->path = std::move(path);
    /* we are doing quite some copies here, sorry about that,
       but we can't keep accessing the req object once we are in a different thread
       because the request might get killed by h2o at pretty much any time */
    if (req->scheme != nullptr) {
      du->scheme = std::string(req->scheme->name.base, req->scheme->name.len);
    }
    du->host = std::string(req->authority.base, req->authority.len);
    du->query_at = req->query_at;
    du->headers.reserve(req->headers.size);
    for (size_t i = 0; i < req->headers.size; ++i) {
      du->headers.push_back(std::make_pair(std::string(req->headers.entries[i].name->base, req->headers.entries[i].name->len),
                                           std::string(req->headers.entries[i].value.base, req->headers.entries[i].value.len)));
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
    catch(...) {
      ptr->release();
    }
  }
  catch(const std::exception& e) {
    vinfolog("Had error parsing DoH DNS packet from %s: %s", remote.toStringWithPort(), e.what());
    h2o_send_error_400(req, "Bad Request", "The DNS query could not be parsed", 0);
  }
}

/* can only be called from the main DoH thread */
static bool getHTTPHeaderValue(const h2o_req_t* req, const std::string& headerName, string_view& value)
{
  bool found = false;
  /* early versions of boost::string_ref didn't have the ability to compare to string */
  string_view headerNameView(headerName);

  for (size_t i = 0; i < req->headers.size; ++i) {
    if (string_view(req->headers.entries[i].name->base, req->headers.entries[i].name->len) == headerNameView) {
      value = string_view(req->headers.entries[i].value.base, req->headers.entries[i].value.len);
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
  string_view value;

  if (getHTTPHeaderValue(req, headerName, value)) {
    try {
      auto pos = value.rfind(',');
      if (pos != string_view::npos) {
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
try
{
  // g_logstream<<(void*)req<<" doh_handler"<<endl;
  if(!req->conn->ctx->storage.size) {
    return 0; // although we might was well crash on this
  }
  h2o_socket_t* sock = req->conn->callbacks->get_socket(req->conn);
  ComboAddress remote;
  ComboAddress local;

  if (h2o_socket_getpeername(sock, reinterpret_cast<struct sockaddr*>(&remote)) == 0) {
    /* getpeername failed, likely because the connection has already been closed,
       but anyway that means we can't get the remote address, which could allow an ACL bypass */
    h2o_send_error_500(req, getReasonFromStatusCode(500).c_str(), "Internal Server Error - Unable to get remote address", 0);
    return 0;
  }

  h2o_socket_getsockname(sock, reinterpret_cast<struct sockaddr*>(&local));
  DOHServerConfig* dsc = reinterpret_cast<DOHServerConfig*>(req->conn->ctx->storage.entries[0].data);

  if (dsc->df->d_trustForwardedForHeader) {
    processForwardedForHeader(req, remote);
  }

  auto& holders = dsc->holders;
  if (!holders.acl->match(remote)) {
    ++g_stats.aclDrops;
    vinfolog("Query from %s (DoH) dropped because of ACL", remote.toStringWithPort());
    h2o_send_error_403(req, "Forbidden", "dns query not allowed because of ACL", 0);
    return 0;
  }

  if (h2o_socket_get_ssl_session_reused(sock) == 0) {
    ++dsc->cs->tlsNewSessions;
  }
  else {
    ++dsc->cs->tlsResumptions;
  }

  if(auto tlsversion = h2o_socket_get_ssl_protocol_version(sock)) {
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

  string path(req->path.base, req->path.len);

  string pathOnly(req->path_normalized.base, req->path_normalized.len);
  if (dsc->paths.count(pathOnly) == 0) {
    h2o_send_error_404(req, "Not Found", "there is no endpoint configured for this path", 0);
    return 0;
  }

  for (const auto& entry : dsc->df->d_responsesMap) {
    if (entry->matches(path)) {
      const auto& customHeaders = entry->getHeaders();
      handleResponse(*dsc->df, req, entry->getStatusCode(), entry->getContent(), customHeaders ? *customHeaders : dsc->df->d_customResponseHeaders, std::string(), false);
      return 0;
    }
  }

  if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("POST"))) {
    ++dsc->df->d_postqueries;
    if(req->version >= 0x0200)
      ++dsc->df->d_http2Stats.d_nbQueries;
    else
      ++dsc->df->d_http1Stats.d_nbQueries;

    std::string query;
    /* We reserve at least 512 additional bytes to be able to add EDNS, but we also want
       at least s_maxPacketCacheEntrySize bytes to be able to fill the answer from the packet cache */
    query.reserve(std::max(req->entity.len + 512, s_maxPacketCacheEntrySize));
    query.assign(req->entity.base, req->entity.len);
    doh_dispatch_query(dsc, self, req, std::move(query), local, remote, std::move(path));
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

      string decoded;
      /* rough estimate so we hopefully don't need a need allocation later */
      /* We reserve at least 512 additional bytes to be able to add EDNS, but we also want
         at least s_maxPacketCacheEntrySize bytes to be able to fill the answer from the packet cache */
      const size_t estimate = ((sdns.size() * 3) / 4);
      decoded.reserve(std::max(estimate + 512, s_maxPacketCacheEntrySize));
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

        doh_dispatch_query(dsc, self, req, std::move(decoded), local, remote, std::move(path));
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

HTTPHeaderRule::HTTPHeaderRule(const std::string& header, const std::string& regex)
  : d_header(toLower(header)), d_regex(regex), d_visual("http[" + header+ "] ~ " + regex)
{
}

bool HTTPHeaderRule::matches(const DNSQuestion* dq) const
{
  if (!dq->du) {
    return false;
  }

  for (const auto& header : dq->du->headers) {
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
  if (!dq->du) {
    return false;
  }

  if (dq->du->query_at == SIZE_MAX) {
    return dq->du->path == d_path;
  }
  else {
    return d_path.compare(0, d_path.size(), dq->du->path, 0, dq->du->query_at) == 0;
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
  if (!dq->du) {
    return false;
  }

  return d_regex.match(dq->du->getHTTPPath());
}

string HTTPPathRegexRule::toString() const
{
  return d_visual;
}

std::unordered_map<std::string, std::string> DOHUnit::getHTTPHeaders() const
{
  std::unordered_map<std::string, std::string> results;
  results.reserve(headers.size());

  for (const auto& header : headers) {
    results.insert(header);
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

void DOHUnit::setHTTPResponse(uint16_t statusCode, const std::string& body_, const std::string& contentType_)
{
  status_code = statusCode;
  response = body_;
  contentType = contentType_;
}

/* query has been parsed by h2o, which called doh_handler() in the main DoH thread.
   In order not to blockfor long, doh_handler() called doh_dispatch_query() which allocated
   a DOHUnit object and passed it to us */
static void dnsdistclient(int qsock)
{
  setThreadName("dnsdist/doh-cli");

  for(;;) {
    try {
      DOHUnit* du = nullptr;
      ssize_t got = read(qsock, &du, sizeof(du));
      if (got < 0) {
        warnlog("Error receiving internal DoH query: %s", strerror(errno));
        continue;
      }
      else if (static_cast<size_t>(got) < sizeof(du)) {
        continue;
      }

      /* we are not in the main DoH thread anymore, so there is a real risk of
         a race condition where h2o kills the query while we are processing it,
         so we can't touch the content of du->req until we are back into the
         main DoH thread */
      if (!du->req) {
        // it got killed in flight already
        du->self = nullptr;
        du->release();
        continue;
      }

      // if there was no EDNS, we add it with a large buffer size
      // so we can use UDP to talk to the backend.
      auto dh = const_cast<struct dnsheader*>(reinterpret_cast<const struct dnsheader*>(du->query.c_str()));

      if (!dh->arcount) {
        std::string res;
        generateOptRR(std::string(), res, 4096, 0, false);

        du->query += res;
        dh = const_cast<struct dnsheader*>(reinterpret_cast<const struct dnsheader*>(du->query.c_str())); // may have reallocated
        dh->arcount = htons(1);
        du->ednsAdded = true;
      }
      else {
        // we leave existing EDNS in place
      }

      if (processDOHQuery(du) < 0) {
        du->status_code = 500;
        /* increase the ref count before sending the pointer */
        du->get();

        static_assert(sizeof(du) <= PIPE_BUF, "Writes up to PIPE_BUF are guaranteed not to be interleaved and to either fully succeed or fail");
        ssize_t sent = write(du->rsock, &du, sizeof(du));
        if (sent != sizeof(du)) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            ++g_stats.dohResponsePipeFull;
            vinfolog("Unable to pass a DoH internal error to the DoH worker thread because the pipe is full");
          }
          else {
            vinfolog("Unable to pass a DoH internal error to the DoH worker thread because we couldn't write to the pipe: %s", stringerror());
          }

          // XXX but now what - will h2o time this out for us?
          du->release();
        }
      }
      du->release();
    }
    catch(const std::exception& e) {
      errlog("Error while processing query received over DoH: %s", e.what());
    }
    catch(...) {
      errlog("Unspecified error while processing query received over DoH");
    }
  }
}

/* Called in the main DoH thread if h2o finds that dnsdist gave us an answer by writing into
   the dohresponsepair[0] side of the pipe so from:
   - handleDOHTimeout() when we did not get a response fast enough (called
     either from the health check thread (active) or from the frontend ones (reused))
   - dnsdistclient (error 500 because processDOHQuery() returned a negative value)
   - processDOHQuery (self-answered queries)
   */
static void on_dnsdist(h2o_socket_t *listener, const char *err)
{
  DOHUnit *du = nullptr;
  DOHServerConfig* dsc = reinterpret_cast<DOHServerConfig*>(listener->data);
  ssize_t got = read(dsc->dohresponsepair[1], &du, sizeof(du));

  if (got < 0) {
    warnlog("Error reading a DOH internal response: %s", strerror(errno));
    return;
  }
  else if (static_cast<size_t>(got) != sizeof(du)) {
    return;
  }

  if (!du->req) { // it got killed in flight
    du->self = nullptr;
    du->release();
    return;
  }

  if (du->self) {
    // we are back in the h2o main thread now, so we don't risk
    // a race (h2o killing the query) when accessing du->req anymore
    *du->self = nullptr; // so we don't clean up again in on_generator_dispose
    du->self = nullptr;
  }

  handleResponse(*dsc->df, du->req, du->status_code, du->response, dsc->df->d_customResponseHeaders, du->contentType, true);

  du->release();
}

/* called when a TCP connection has been accepted, the TLS session has not been established */
static void on_accept(h2o_socket_t *listener, const char *err)
{
  DOHServerConfig* dsc = reinterpret_cast<DOHServerConfig*>(listener->data);
  h2o_socket_t *sock = nullptr;

  if (err != nullptr) {
    return;
  }
  // do some dnsdist rules here to filter based on IP address
  if ((sock = h2o_evloop_socket_accept(listener)) == nullptr) {
    return;
  }

  // ComboAddress remote;
  // h2o_socket_getpeername(sock, reinterpret_cast<struct sockaddr*>(&remote));
  //  cout<<"New HTTP accept for client "<<remote.toStringWithPort()<<": "<< listener->data << endl;

  sock->data = dsc;
  sock->on_close.cb = on_socketclose;
  auto accept_ctx = dsc->accept_ctx->get();
  sock->on_close.data = dsc->accept_ctx;
  ++dsc->df->d_httpconnects;
  ++dsc->cs->tcpCurrentConnections;
  h2o_accept(accept_ctx, sock);
}

static int create_listener(const ComboAddress& addr, std::shared_ptr<DOHServerConfig>& dsc, int fd)
{
  auto sock = h2o_evloop_socket_create(dsc->h2o_ctx.loop, fd, H2O_SOCKET_FLAG_DONT_READ);
  sock->data = dsc.get();
  h2o_socket_read_start(sock, on_accept);

  return 0;
}

static int ocsp_stapling_callback(SSL* ssl, void* arg)
{
  if (ssl == nullptr || arg == nullptr) {
    return SSL_TLSEXT_ERR_NOACK;
  }
  const auto ocspMap = reinterpret_cast<std::map<int, std::string>*>(arg);
  return libssl_ocsp_stapling_callback(ssl, *ocspMap);
}

static int ticket_key_callback(SSL *s, unsigned char keyName[TLS_TICKETS_KEY_NAME_SIZE], unsigned char *iv, EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc)
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

  auto ctx = libssl_init_server_context(tlsConfig, acceptCtx.d_ocspResponses);

  if (tlsConfig.d_enableTickets && tlsConfig.d_numberOfTicketsKeys > 0) {
    acceptCtx.d_ticketKeys = std::unique_ptr<OpenSSLTLSTicketKeysRing>(new OpenSSLTLSTicketKeysRing(tlsConfig.d_numberOfTicketsKeys));
    SSL_CTX_set_tlsext_ticket_key_cb(ctx.get(), &ticket_key_callback);
    libssl_set_ticket_key_callback_data(ctx.get(), &acceptCtx);
  }

  if (!acceptCtx.d_ocspResponses.empty()) {
    SSL_CTX_set_tlsext_status_cb(ctx.get(), &ocsp_stapling_callback);
    SSL_CTX_set_tlsext_status_arg(ctx.get(), &acceptCtx.d_ocspResponses);
  }

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
  acceptCtx.release();
}

static void setupAcceptContext(DOHAcceptContext& ctx, DOHServerConfig& dsc, bool setupTLS)
{
  auto nativeCtx = ctx.get();
  nativeCtx->ctx = &dsc.h2o_ctx;
  nativeCtx->hosts = dsc.h2o_config.hosts;
  ctx.d_ticketsKeyRotationDelay = dsc.df->d_tlsConfig.d_ticketsKeyRotationDelay;

  if (setupTLS && !dsc.df->d_tlsConfig.d_certKeyPairs.empty()) {
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
  ctx.release();
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
  auto newAcceptContext = std::unique_ptr<DOHAcceptContext>(new DOHAcceptContext());
  setupAcceptContext(*newAcceptContext, *d_dsc, true);
  DOHAcceptContext* oldCtx = d_dsc->accept_ctx;
  d_dsc->accept_ctx = newAcceptContext.release();
  oldCtx->release();
}

void DOHFrontend::setup()
{
  registerOpenSSLUser();

  d_dsc = std::make_shared<DOHServerConfig>(d_idleTimeout, d_internalPipeBufferSize);

  if  (!d_tlsConfig.d_certKeyPairs.empty()) {
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
try
{
  std::shared_ptr<DOHFrontend>& df = cs->dohFrontend;
  auto& dsc = df->d_dsc;
  dsc->cs = cs;
  dsc->df = cs->dohFrontend;
  dsc->h2o_config.server_name = h2o_iovec_init(df->d_serverTokens.c_str(), df->d_serverTokens.size());


  std::thread dnsdistThread(dnsdistclient, dsc->dohquerypair[1]);
  dnsdistThread.detach(); // gets us better error reporting

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

  if (create_listener(df->d_local, dsc, cs->tcpFD) != 0) {
    throw std::runtime_error("DOH server failed to listen on " + df->d_local.toStringWithPort() + ": " + strerror(errno));
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
catch(const std::exception& e) {
  throw runtime_error("DOH thread failed to launch: " + std::string(e.what()));
}
catch(...) {
  throw runtime_error("DOH thread failed to launch");
}

#else /* HAVE_DNS_OVER_HTTPS */

void handleDOHTimeout(DOHUnit* oldDU)
{
}

#endif /* HAVE_DNS_OVER_HTTPS */
