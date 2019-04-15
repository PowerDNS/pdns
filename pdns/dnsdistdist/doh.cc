#define H2O_USE_EPOLL 1
#include <errno.h>
#include <iostream>
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http2.h"
#include "base64.hh"
#include "dnsname.hh"
#undef CERT
#include "dnsdist.hh"
#include "misc.hh"
#include <thread>
#include "dns.hh"
#include "dolog.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-rules.hh"
#include "dnsdist-xpf.hh"
#include <boost/algorithm/string.hpp>

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

// we create one of these per thread, and pass around a pointer to it
// through the bowels of h2o
struct DOHServerConfig
{
  DOHServerConfig(ClientState* cs_): cs(cs_), df(cs_->dohFrontend)
  {
    memset(&h2o_accept_ctx, 0, sizeof(h2o_accept_ctx));

    if(socketpair(AF_LOCAL, SOCK_DGRAM, 0, dohquerypair) < 0) {
      unixDie("Creating a socket pair for DNS over HTTPS");
    }

    if (socketpair(AF_LOCAL, SOCK_DGRAM, 0, dohresponsepair) < 0) {
      close(dohquerypair[0]);
      close(dohquerypair[1]);
      unixDie("Creating a socket pair for DNS over HTTPS");
    }

    h2o_config_init(&h2o_config);
    h2o_config.http2.idle_timeout = df->d_idleTimeout * 1000;
  }

  h2o_globalconf_t h2o_config;
  h2o_context_t h2o_ctx;
  h2o_accept_ctx_t h2o_accept_ctx;
  ClientState* cs{nullptr};
  std::shared_ptr<DOHFrontend> df{nullptr};
  int dohquerypair[2]{-1,-1};
  int dohresponsepair[2]{-1,-1};
};

/* this duplicates way too much from the UDP handler. Sorry.
   this function calls 'return -1' to drop a query without sending it
   caller should make sure HTTPS thread hears of that
*/

static int processDOHQuery(DOHUnit* du)
{
  LocalHolders holders;
  uint16_t queryId = 0;
  try {
    if(!du->req) {
      // we got closed meanwhile. XXX small race condition here
      return -1;
    }
    DOHServerConfig* dsc = (DOHServerConfig*)du->req->conn->ctx->storage.entries[0].data;
    ClientState& cs = *dsc->cs;

    if (du->query.size() < sizeof(dnsheader)) {
      ++g_stats.nonCompliantQueries;
      return -1;
    }

    if(!holders.acl->match(du->remote)) {
      vinfolog("Query from %s (DoH) dropped because of ACL", du->remote.toStringWithPort());
      ++g_stats.aclDrops;
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
      return -1; // drop
    }

    uint16_t qtype, qclass;
    unsigned int consumed = 0;
    DNSName qname(query, len, sizeof(dnsheader), false, &qtype, &qclass, &consumed);
    DNSQuestion dq(&qname, qtype, qclass, consumed, &du->dest, &du->remote, dh, bufferSize, len, false, &queryRealTime);
    dq.ednsAdded = du->ednsAdded;
    dq.du = du;
    queryId = ntohs(dh->id);

    std::shared_ptr<DownstreamState> ss{nullptr};
    auto result = processQuery(dq, cs, holders, ss);

    if (result == ProcessQueryResult::Drop) {
      return -1;
    }

    if (result == ProcessQueryResult::SendAnswer) {
      du->query = std::string(reinterpret_cast<char*>(dq.dh), dq.len);
      send(du->rsock, &du, sizeof(du), 0);
      return 0;
    }

    if (result != ProcessQueryResult::PassToBackend || ss == nullptr) {
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
    ssize_t ret = udpClientSendRequestToBackend(ss, fd, query, dq.len);

    if(ret < 0) {
      ++ss->sendErrors;
      ++g_stats.downstreamSendErrors;
    }

    vinfolog("Got query for %s|%s from %s (https), relayed to %s", ids->qname.toString(), QType(ids->qtype).getName(), du->remote.toStringWithPort(), ss->getName());
  }
  catch(const std::exception& e) {
    vinfolog("Got an error in DOH question thread while parsing a query from %s, id %d: %s", du->remote.toStringWithPort(), queryId, e.what());
    return -1;
  }
  return 0;
}

static h2o_pathconf_t *register_handler(h2o_hostconf_t *hostconf, const char *path, int (*on_req)(h2o_handler_t *, h2o_req_t *))
{
  h2o_pathconf_t *pathconf = h2o_config_register_path(hostconf, path, 0);
  h2o_handler_t *handler = h2o_create_handler(pathconf, sizeof(*handler));
  handler->on_req = on_req;
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

static void doh_dispatch_query(DOHServerConfig* dsc, h2o_handler_t* self, h2o_req_t* req, std::string&& query, ComboAddress& remote)
{
  try {
    auto du = std::unique_ptr<DOHUnit>(new DOHUnit);
    du->self = reinterpret_cast<DOHUnit**>(h2o_mem_alloc_shared(&req->pool, sizeof(*self), on_generator_dispose));
    uint16_t qtype;
    DNSName qname(query.c_str(), query.size(), sizeof(dnsheader), false, &qtype);
    du->req = req;
    du->query = std::move(query);
    du->remote = remote;
    du->rsock = dsc->dohresponsepair[0];
    du->qtype = qtype;
    auto ptr = du.release();
    *(ptr->self) = ptr;
    try  {
      if(send(dsc->dohquerypair[0], &ptr, sizeof(ptr), 0) != sizeof(ptr)) {
        delete ptr;     // XXX but now what - will h2o time this out for us?
        ptr = nullptr;
      }
    }
    catch(...) {
      delete ptr;
    }
  }
  catch(const std::exception& e) {
    vinfolog("Had error parsing DoH DNS packet from %s: %s", remote.toStringWithPort(), e.what());
    h2o_send_error_400(req, "Bad Request", "dnsdist " VERSION " could not parse DNS query", 0);
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
  h2o_socket_getpeername(sock, reinterpret_cast<struct sockaddr*>(&remote));
  DOHServerConfig* dsc = (DOHServerConfig*)req->conn->ctx->storage.entries[0].data;

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
      ++dsc->df->d_http2queries;
    else
      ++dsc->df->d_http1queries;

    std::string query;
    query.reserve(req->entity.len + 512);
    query.assign(req->entity.base, req->entity.len);
    doh_dispatch_query(dsc, self, req, std::move(query), remote);
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
      sdns.append(sdns.size() % 4, '='); // re-add padding that may have been missing

      string decoded;
      /* rough estimate so we hopefully don't need a need allocation later */
      decoded.reserve(((sdns.size() * 3) / 4) + 512);
      if(B64Decode(sdns, decoded) < 0) {
        h2o_send_error_400(req, "Bad Request", "dnsdist " VERSION " could not decode BASE64-URL", 0);
        ++dsc->df->d_badrequests;
        return 0;
      }
      else {
        ++dsc->df->d_getqueries;
        if(req->version >= 0x0200)
          ++dsc->df->d_http2queries;
        else
          ++dsc->df->d_http1queries;

        doh_dispatch_query(dsc, self, req, std::move(decoded), remote);
      }
    }
    else
    {
      vinfolog("HTTP request without DNS parameter: %s", req->path.base);
      h2o_send_error_400(req, "Bad Request", "dnsdist " VERSION " could not find DNS parameter", 0);
      ++dsc->df->d_badrequests;
      return 0;
    }
  }
  else {
    h2o_send_error_400(req, "Bad Request", "dnsdist " VERSION " could not parse your request", 0);
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
  DOHServerConfig* dsc = (DOHServerConfig*)listener->data;
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
  if(!du->error) {
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
    h2o_send_error_500(du->req, "Internal Server Error", "Internal Server Error", 0);
    ++dsc->df->d_errorresponses;
  }
  delete du;
}

static void on_accept(h2o_socket_t *listener, const char *err)
{
  DOHServerConfig* dsc = (DOHServerConfig*)listener->data;
  h2o_socket_t *sock = nullptr;

  if (err != nullptr) {
    return;
  }
  // do some dnsdist rules here to filter based on IP address
  if ((sock = h2o_evloop_socket_accept(listener)) == nullptr)
    return;

  ComboAddress remote;

  h2o_socket_getpeername(sock, reinterpret_cast<struct sockaddr*>(&remote));
  //  cout<<"New HTTP accept for client "<<remote.toStringWithPort()<<": "<< listener->data << endl;

  sock->data = dsc;
  ++dsc->df->d_httpconnects;
  h2o_accept(&dsc->h2o_accept_ctx, sock);
}

static int create_listener(const ComboAddress& addr, DOHServerConfig* dsc, int fd)
{
  auto sock = h2o_evloop_socket_create(dsc->h2o_ctx.loop, fd, H2O_SOCKET_FLAG_DONT_READ);
  sock->data = (void*) dsc;
  h2o_socket_read_start(sock, on_accept);

  return 0;
}

static int setup_ssl(DOHServerConfig* dsc, const char *cert_file, const char *key_file, const char *ciphers)
{
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();

  dsc->h2o_accept_ctx.ssl_ctx = SSL_CTX_new(SSLv23_server_method());

  SSL_CTX_set_options(dsc->h2o_accept_ctx.ssl_ctx, SSL_OP_NO_SSLv2);

#ifdef SSL_CTX_set_ecdh_auto
  SSL_CTX_set_ecdh_auto(dsc->h2o_accept_ctx.ssl_ctx, 1);
#endif

  /* load certificate and private key */
  if (SSL_CTX_use_certificate_chain_file(dsc->h2o_accept_ctx.ssl_ctx, cert_file) != 1) {
    fprintf(stderr, "an error occurred while trying to load server certificate file:%s\n", cert_file);
    return -1;
  }
  if (SSL_CTX_use_PrivateKey_file(dsc->h2o_accept_ctx.ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
    fprintf(stderr, "an error occurred while trying to load private key file:%s\n", key_file);
    return -1;
  }

  if (SSL_CTX_set_cipher_list(dsc->h2o_accept_ctx.ssl_ctx, ciphers) != 1) {
    fprintf(stderr, "ciphers could not be set: %s\n", ciphers);
    return -1;
  }

  h2o_ssl_register_alpn_protocols(dsc->h2o_accept_ctx.ssl_ctx, h2o_http2_alpn_protocols);

  return 0;
}

void DOHFrontend::setup()
{
}

// this is the entrypoint from dnsdist.cc
void dohThread(ClientState* cs)
try
{
  std::shared_ptr<DOHFrontend>& df = cs->dohFrontend;
  auto dsc = new DOHServerConfig(cs);

  std::thread dnsdistThread(dnsdistclient, dsc->dohquerypair[1], dsc->dohresponsepair[0]);
  dnsdistThread.detach(); // gets us better error reporting

  // I wonder if this registers an IP address.. I think it does
  // this may mean we need to actually register a site "name" here and not the IP address
  h2o_hostconf_t *hostconf = h2o_config_register_host(&dsc->h2o_config, h2o_iovec_init(df->d_local.toString().c_str(), df->d_local.toString().size()), 65535);

  for(const auto& url : df->d_urls) {
    register_handler(hostconf, url.c_str(), doh_handler);
  }

  h2o_context_init(&dsc->h2o_ctx, h2o_evloop_create(), &dsc->h2o_config);

  // in this complicated way we insert the DOHServerConfig pointer in there
  h2o_vector_reserve(nullptr, &dsc->h2o_ctx.storage, 1);
  dsc->h2o_ctx.storage.entries[0].data = (void*)dsc;
  ++dsc->h2o_ctx.storage.size;

  auto sock = h2o_evloop_socket_create(dsc->h2o_ctx.loop, dsc->dohresponsepair[1], H2O_SOCKET_FLAG_DONT_READ);
  sock->data = dsc;

  // this listens to responses from dnsdist to turn into http responses
  h2o_socket_read_start(sock, on_dnsdist);

  // we should probably make that hash, algorithm etc line configurable too
  if(setup_ssl(dsc, df->d_certFile.c_str(), df->d_keyFile.c_str(),
                "DEFAULT:!MD5:!DSS:!DES:!RC4:!RC2:!SEED:!IDEA:!NULL:!ADH:!EXP:!SRP:!PSK") != 0)
    throw std::runtime_error("Failed to setup SSL/TLS for DoH listener");

  // as one does
  dsc->h2o_accept_ctx.ctx = &dsc->h2o_ctx;
  dsc->h2o_accept_ctx.hosts = dsc->h2o_config.hosts;

  if (create_listener(df->d_local, dsc, cs->tcpFD) != 0) {
    throw std::runtime_error("DOH server failed to listen on " + df->d_local.toStringWithPort() + ": " + strerror(errno));
  }

  while (h2o_evloop_run(dsc->h2o_ctx.loop, INT32_MAX) == 0)
    ;
 }
 catch(const std::exception& e) {
   throw runtime_error("DOH thread failed to launch: " + std::string(e.what()));
 }
 catch(...) {
   throw runtime_error("DOH thread failed to launch");
 }
