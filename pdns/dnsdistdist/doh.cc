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
#include "dnsdist-rules.hh"
#include "dnsdist-xpf.hh"
#include "libssl.hh"
#include "threadname.hh"

using namespace std;

/* So, how does this work. We use h2o for our http2 and TLS needs.
   If the operator has configured multiple IP addresses to listen on,
   we launch multiple h2o listener threads. We can hook in to multiple
   URLs though on the same IP. There is no SNI yet (I think).

   h2o is event driven, so we get callbacks if a new DNS query arrived.
   When it does, we do some minimal parsing on it, and send it on to the
   dnsdist worker thread which we also launched.

   This dnsdist worker thread injects the query into the normal dnsdist flow
   (as a datagram over a socketpair). The response also goes back over a
   (different) socketpair, where we pick it up and deliver it back to h2o.

   For coordination, we use the h2o socket multiplexer, which is sensitive to our
   socketpair too.
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
    --d_refcnt;
    if (d_refcnt == 0) {
      SSL_CTX_free(d_h2o_accept_ctx.ssl_ctx);
      d_h2o_accept_ctx.ssl_ctx = nullptr;
      delete this;
    }
  }

private:
  h2o_accept_ctx_t d_h2o_accept_ctx;
  std::atomic<uint64_t> d_refcnt{1};
};

// we create one of these per thread, and pass around a pointer to it
// through the bowels of h2o
struct DOHServerConfig
{
  DOHServerConfig(uint32_t idleTimeout): accept_ctx(new DOHAcceptContext)
  {
    if(socketpair(AF_LOCAL, SOCK_DGRAM, 0, dohquerypair) < 0) {
      unixDie("Creating a socket pair for DNS over HTTPS");
    }

    if (socketpair(AF_LOCAL, SOCK_DGRAM, 0, dohresponsepair) < 0) {
      close(dohquerypair[0]);
      close(dohquerypair[1]);
      unixDie("Creating a socket pair for DNS over HTTPS");
    }

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
  h2o_globalconf_t h2o_config;
  h2o_context_t h2o_ctx;
  DOHAcceptContext* accept_ctx{nullptr};
  ClientState* cs{nullptr};
  std::shared_ptr<DOHFrontend> df{nullptr};
  int dohquerypair[2]{-1,-1};
  int dohresponsepair[2]{-1,-1};
};

static void on_socketclose(void *data)
{
  DOHAcceptContext* ctx = reinterpret_cast<DOHAcceptContext*>(data);
  ctx->release();
}

/* this duplicates way too much from the UDP handler. Sorry.
   this function calls 'return -1' to drop a query without sending it
   caller should make sure HTTPS thread hears of that
*/

static int processDOHQuery(DOHUnit* du)
{
  uint16_t queryId = 0;
  ComboAddress remote;
  try {
    if(!du->req) {
      // we got closed meanwhile. XXX small race condition here
      return -1;
    }
    remote = du->remote;
    DOHServerConfig* dsc = reinterpret_cast<DOHServerConfig*>(du->req->conn->ctx->storage.entries[0].data);
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
    /* allocate a bit more memory to be able to spoof the content,
       or to add ECS without allocating a new buffer */
    du->query.resize(du->query.size() + 512);
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
#ifdef HAVE_H2O_SOCKET_GET_SSL_SERVER_NAME
    h2o_socket_t* sock = du->req->conn->callbacks->get_socket(du->req->conn);
    const char * sni = h2o_socket_get_ssl_server_name(sock);
    if (sni != nullptr) {
      dq.sni = sni;
    }
#endif /* HAVE_H2O_SOCKET_BET_SSL_SERVER_NAME */

    std::shared_ptr<DownstreamState> ss{nullptr};
    auto result = processQuery(dq, cs, holders, ss);

    if (result == ProcessQueryResult::Drop) {
      du->status_code = 403;
      return -1;
    }

    if (result == ProcessQueryResult::SendAnswer) {
      du->query = std::string(reinterpret_cast<char*>(dq.dh), dq.len);
      send(du->rsock, &du, sizeof(du), 0);
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

    unsigned int idOffset = (ss->idOffset++) % ss->idStates.size();
    IDState* ids = &ss->idStates[idOffset];
    ids->age = 0;
    ids->du = du;

    int oldFD = ids->origFD.exchange(cs.udpFD);
    if(oldFD < 0) {
      // if we are reusing, no change in outstanding
      ++ss->outstanding;
    }
    else {
      ++ss->reuseds;
      ++g_stats.downstreamTimeouts;
    }

    ids->cs = &cs;
    ids->origID = dh->id;
    setIDStateFromDNSQuestion(*ids, dq, std::move(qname));

    /* If we couldn't harvest the real dest addr, still
       write down the listening addr since it will be useful
       (especially if it's not an 'any' one).
       We need to keep track of which one it is since we may
       want to use the real but not the listening addr to reply.
    */
    if (du->dest.sin4.sin_family != 0) {
      ids->origDest = du->dest;
      ids->destHarvested = true;
    }
    else {
      ids->origDest = cs.local;
      ids->destHarvested = false;
    }

    dh->id = idOffset;

    int fd = pickBackendSocketForSending(ss);
    /* you can't touch du after this line, because it might already have been freed */
    ssize_t ret = udpClientSendRequestToBackend(ss, fd, query, dq.len);

    vinfolog("Got query for %s|%s from %s (https), relayed to %s", ids->qname.toString(), QType(ids->qtype).getName(), remote.toStringWithPort(), ss->getName());

    if(ret < 0) {
      ++ss->sendErrors;
      ++g_stats.downstreamSendErrors;
      du->status_code = 502;
      return -1;
    }
  }
  catch(const std::exception& e) {
    vinfolog("Got an error in DOH question thread while parsing a query from %s, id %d: %s", remote.toStringWithPort(), queryId, e.what());
    du->status_code = 500;
    return -1;
  }

  return 0;
}

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

/* this is called by h2o when our request dies.
   We use this to signal to the 'du' that this req is no longer alive */
static void on_generator_dispose(void *_self)
{
  DOHUnit** du = (DOHUnit**)_self;
  if(*du) { // if 0, on_dnsdist cleaned up du already
//    cout << "du "<<(void*)*du<<" containing req "<<(*du)->req<<" got killed"<<endl;
    (*du)->req = nullptr;
  }
}

static void doh_dispatch_query(DOHServerConfig* dsc, h2o_handler_t* self, h2o_req_t* req, std::string&& query, const ComboAddress& local, const ComboAddress& remote)
{
  try {
    uint16_t qtype;
    DNSName qname(query.c_str(), query.size(), sizeof(dnsheader), false, &qtype);

    auto du = std::unique_ptr<DOHUnit>(new DOHUnit);
    du->req = req;
    du->dest = local;
    du->remote = remote;
    du->rsock = dsc->dohresponsepair[0];
    du->query = std::move(query);
    du->qtype = qtype;
    du->self = reinterpret_cast<DOHUnit**>(h2o_mem_alloc_shared(&req->pool, sizeof(*self), on_generator_dispose));
    auto ptr = du.release();
    *(ptr->self) = ptr;
    try  {
      if(send(dsc->dohquerypair[0], &ptr, sizeof(ptr), 0) != sizeof(ptr)) {
        delete ptr;
        ptr = nullptr;
        h2o_send_error_500(req, "Internal Server Error", "Internal Server Error", 0);
      }
    }
    catch(...) {
      delete ptr;
    }
  }
  catch(const std::exception& e) {
    vinfolog("Had error parsing DoH DNS packet from %s: %s", remote.toStringWithPort(), e.what());
    h2o_send_error_400(req, "Bad Request", "The DNS query could not be parsed", 0);
  }
}

/*
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
  h2o_socket_getpeername(sock, reinterpret_cast<struct sockaddr*>(&remote));
  h2o_socket_getsockname(sock, reinterpret_cast<struct sockaddr*>(&local));
  DOHServerConfig* dsc = reinterpret_cast<DOHServerConfig*>(req->conn->ctx->storage.entries[0].data);

  auto& holders = dsc->holders;
  if (!holders.acl->match(remote)) {
    ++g_stats.aclDrops;
    vinfolog("Query from %s (DoH) dropped because of ACL", remote.toStringWithPort());
    h2o_send_error_403(req, "Forbidden", "dns query not allowed because of ACL", 0);
    return 0;
  }

  if(auto tlsversion = h2o_socket_get_ssl_protocol_version(sock)) {
    if(!strcmp(tlsversion, "TLSv1.0"))
      ++dsc->df->d_tls10queries;
    else if(!strcmp(tlsversion, "TLSv1.1"))
      ++dsc->df->d_tls11queries;
    else if(!strcmp(tlsversion, "TLSv1.2"))
      ++dsc->df->d_tls12queries;
    else if(!strcmp(tlsversion, "TLSv1.3"))
      ++dsc->df->d_tls13queries;
    else
      ++dsc->df->d_tlsUnknownqueries;
  }

  string path(req->path.base, req->path.len);

  if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("POST"))) {
    ++dsc->df->d_postqueries;
    if(req->version >= 0x0200)
      ++dsc->df->d_http2Stats.d_nbQueries;
    else
      ++dsc->df->d_http1Stats.d_nbQueries;

    std::string query;
    query.reserve(req->entity.len + 512);
    query.assign(req->entity.base, req->entity.len);
    doh_dispatch_query(dsc, self, req, std::move(query), local, remote);
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
      decoded.reserve(((sdns.size() * 3) / 4) + 512);
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

        doh_dispatch_query(dsc, self, req, std::move(decoded), local, remote);
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
catch(const exception& e)
{
  errlog("DOH Handler function failed with error %s", e.what());
  return 0;
}

HTTPHeaderRule::HTTPHeaderRule(const std::string& header, const std::string& regex)
  :  d_regex(regex)
{
  d_header = toLower(header);
  d_visual = "http[" + header+ "] ~ " + regex;

}
bool HTTPHeaderRule::matches(const DNSQuestion* dq) const
{
  if(!dq->du) {
    return false;
  }

  for (unsigned int i = 0; i != dq->du->req->headers.size; ++i) {
    if(std::string(dq->du->req->headers.entries[i].name->base, dq->du->req->headers.entries[i].name->len) == d_header &&
       d_regex.match(std::string(dq->du->req->headers.entries[i].value.base, dq->du->req->headers.entries[i].value.len))) {
      return true;
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
  if(!dq->du) {
    return false;
  }

  if(dq->du->req->query_at == SIZE_MAX) {
    return dq->du->req->path.base == d_path;
  }
  else {
    return d_path.compare(0, d_path.size(), dq->du->req->path.base, dq->du->req->query_at) == 0;
  }
}

string HTTPPathRule::toString() const
{
  return "url path == " + d_path;
}

void dnsdistclient(int qsock, int rsock)
{
  setThreadName("dnsdist/doh-cli");

  for(;;) {
    try {
      DOHUnit* du = nullptr;
      ssize_t got = recv(qsock, &du, sizeof(du), 0);
      if (got < 0) {
        warnlog("Error receving internal DoH query: %s", strerror(errno));
        continue;
      }
      else if (static_cast<size_t>(got) < sizeof(du)) {
        continue;
      }

      // if there was no EDNS, we add it with a large buffer size
      // so we can use UDP to talk to the backend.
      auto dh = const_cast<struct dnsheader*>(reinterpret_cast<const struct dnsheader*>(du->query.c_str()));

      if(!dh->arcount) {
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

      if(processDOHQuery(du) < 0) {
        du->error = true; // turns our drop into a 500
        if(send(du->rsock, &du, sizeof(du), 0) != sizeof(du))
          delete du;     // XXX but now what - will h2o time this out for us?
      }
    }
    catch(const std::exception& e) {
      errlog("Error while processing query received over DoH: %s", e.what());
    }
    catch(...) {
      errlog("Unspecified error while processing query received over DoH");
    }
  }
}

// called if h2o finds that dnsdist gave us an answer
static void on_dnsdist(h2o_socket_t *listener, const char *err)
{
  DOHUnit *du = nullptr;
  DOHServerConfig* dsc = reinterpret_cast<DOHServerConfig*>(listener->data);
  ssize_t got = recv(dsc->dohresponsepair[1], &du, sizeof(du), 0);

  if (got < 0) {
    warnlog("Error reading a DOH internal response: %s", strerror(errno));
    return;
  }
  else if (static_cast<size_t>(got) != sizeof(du)) {
    return;
  }

  if(!du->req) { // it got killed in flight
//    cout << "du "<<(void*)du<<" came back from dnsdist, but it was killed"<<endl;
    delete du;
    return;
  }

  *du->self = nullptr; // so we don't clean up again in on_generator_dispose
  if (!du->error) {
    ++dsc->df->d_validresponses;
    du->req->res.status = 200;
    du->req->res.reason = "OK";

    h2o_add_header(&du->req->pool, &du->req->res.headers, H2O_TOKEN_CONTENT_TYPE, nullptr, H2O_STRLIT("application/dns-message"));

    //    struct dnsheader* dh = (struct dnsheader*)du->query.c_str();
    //    cout<<"Attempt to send out "<<du->query.size()<<" bytes over https, TC="<<dh->tc<<", RCODE="<<dh->rcode<<", qtype="<<du->qtype<<", req="<<(void*)du->req<<endl;

    du->req->res.content_length = du->query.size();
    h2o_send_inline(du->req, du->query.c_str(), du->query.size());
  }
  else {
    switch(du->status_code) {
    case 400:
      h2o_send_error_400(du->req, "Bad Request", "invalid DNS query", 0);
      break;
    case 403:
      h2o_send_error_403(du->req, "Forbidden", "dns query not allowed", 0);
      break;
    case 502:
      h2o_send_error_502(du->req, "Bad Gateway", "no downstream server available", 0);
      break;
    case 500:
      /* fall-through */
    default:
      h2o_send_error_500(du->req, "Internal Server Error", "Internal Server Error", 0);
      break;
    }

    ++dsc->df->d_errorresponses;
  }
  delete du;
}

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

  ComboAddress remote;
  h2o_socket_getpeername(sock, reinterpret_cast<struct sockaddr*>(&remote));
  //  cout<<"New HTTP accept for client "<<remote.toStringWithPort()<<": "<< listener->data << endl;

  sock->data = dsc;
  sock->on_close.cb = on_socketclose;
  auto accept_ctx = dsc->accept_ctx->get();
  sock->on_close.data = dsc->accept_ctx;
  ++dsc->df->d_httpconnects;
  h2o_accept(accept_ctx, sock);
}

static int create_listener(const ComboAddress& addr, std::shared_ptr<DOHServerConfig>& dsc, int fd)
{
  auto sock = h2o_evloop_socket_create(dsc->h2o_ctx.loop, fd, H2O_SOCKET_FLAG_DONT_READ);
  sock->data = dsc.get();
  h2o_socket_read_start(sock, on_accept);

  return 0;
}

static std::unique_ptr<SSL_CTX, void(*)(SSL_CTX*)> getTLSContext(const std::vector<std::pair<std::string, std::string>>& pairs, const std::string& ciphers, const std::string& ciphers13)
{
  auto ctx = std::unique_ptr<SSL_CTX, void(*)(SSL_CTX*)>(SSL_CTX_new(SSLv23_server_method()), SSL_CTX_free);

  int sslOptions =
    SSL_OP_NO_SSLv2 |
    SSL_OP_NO_SSLv3 |
    SSL_OP_NO_COMPRESSION |
    SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
    SSL_OP_SINGLE_DH_USE |
    SSL_OP_SINGLE_ECDH_USE;

  SSL_CTX_set_options(ctx.get(), sslOptions);

#ifdef SSL_CTX_set_ecdh_auto
  SSL_CTX_set_ecdh_auto(ctx.get(), 1);
#endif

  /* load certificate and private key */
  for (const auto& pair : pairs) {
    if (SSL_CTX_use_certificate_chain_file(ctx.get(), pair.first.c_str()) != 1) {
      ERR_print_errors_fp(stderr);
      throw std::runtime_error("Failed to setup SSL/TLS for DoH listener, an error occurred while trying to load the DOH server certificate file: " + pair.first);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx.get(), pair.second.c_str(), SSL_FILETYPE_PEM) != 1) {
      ERR_print_errors_fp(stderr);
      throw std::runtime_error("Failed to setup SSL/TLS for DoH listener, an error occurred while trying to load the DOH server private key file: " + pair.second);
    }
  }

  if (SSL_CTX_set_cipher_list(ctx.get(), ciphers.empty() == false ? ciphers.c_str() : DOH_DEFAULT_CIPHERS) != 1) {
    throw std::runtime_error("Failed to setup SSL/TLS for DoH listener, DOH ciphers could not be set: " + ciphers);
  }

#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
  if (!ciphers13.empty() && SSL_CTX_set_ciphersuites(ctx.get(), ciphers13.c_str()) != 1) {
    throw std::runtime_error("Failed to setup SSL/TLS for DoH listener, DOH TLS 1.3 ciphers could not be set: " + ciphers13);
  }
#endif /* HAVE_SSL_CTX_SET_CIPHERSUITES */

  h2o_ssl_register_alpn_protocols(ctx.get(), h2o_http2_alpn_protocols);

  return ctx;
}

static void setupAcceptContext(DOHAcceptContext& ctx, DOHServerConfig& dsc, bool setupTLS)
{
  auto nativeCtx = ctx.get();
  nativeCtx->ctx = &dsc.h2o_ctx;
  nativeCtx->hosts = dsc.h2o_config.hosts;
  if (setupTLS) {
    auto tlsCtx = getTLSContext(dsc.df->d_certKeyPairs,
                                dsc.df->d_ciphers,
                                dsc.df->d_ciphers13);

    nativeCtx->ssl_ctx = tlsCtx.release();
  }

  ctx.release();
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

  d_dsc = std::make_shared<DOHServerConfig>(d_idleTimeout);

  auto tlsCtx = getTLSContext(d_certKeyPairs,
                              d_ciphers,
                              d_ciphers13);

  auto accept_ctx = d_dsc->accept_ctx->get();
  accept_ctx->ssl_ctx = tlsCtx.release();
  d_dsc->accept_ctx->release();
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


  std::thread dnsdistThread(dnsdistclient, dsc->dohquerypair[1], dsc->dohresponsepair[0]);
  dnsdistThread.detach(); // gets us better error reporting

  setThreadName("dnsdist/doh");
  // I wonder if this registers an IP address.. I think it does
  // this may mean we need to actually register a site "name" here and not the IP address
  h2o_hostconf_t *hostconf = h2o_config_register_host(&dsc->h2o_config, h2o_iovec_init(df->d_local.toString().c_str(), df->d_local.toString().size()), 65535);

  for(const auto& url : df->d_urls) {
    register_handler(hostconf, url.c_str(), doh_handler);
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
