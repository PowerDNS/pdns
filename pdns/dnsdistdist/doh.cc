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
#include <boost/algorithm/string.hpp>
using namespace std;

/* So, how does this work. We use h2o for our http2 and TLS needs. 
   If the operator has configured multiple IP addresses to listen on, 
   we launch multiple h2o listener threads. 

   h2o is event driven, so we get callbacks if a new DNS query arrived.
   When it does, we do some minimal parsing on it, and send it on to the 
   dnsdist worker thread which we also launched.

   This dnsdist worker thread injects the query into the normal dnsdist flow 
   (as a datagram over a socketpair). The response also goes back over a 
   (different) socketpair, where we pick it up and deliver it back to h2o.

   For coordination, we use the h2o socket multiplexer, which is sensitive to our
   socketpair too.
*/

// we create on of these per thread, and pass around a pointer to it
// through the bowels of h2o
struct DOHServerConfig
{
  h2o_globalconf_t h2o_config;
  h2o_context_t h2o_ctx;
  h2o_accept_ctx_t h2o_accept_ctx;

  int dohquerypair[2];
  int dohresponsepair[2];
  ClientState cs;
};

// this duplicates way too much from the UDP handler
static void processDOHQuery(DOHUnit* du)
{
  LocalHolders holders;
  uint16_t queryId=0;
  try {
    DOHServerConfig* dsc = (DOHServerConfig*)du->req->conn->ctx->storage.entries[0].data;
    ClientState& cs = dsc->cs;
    cs.muted=false; // cs is not filled out so we have to force this
    
    /* we need an accurate ("real") value for the response and
       to store into the IDS, but not for insertion into the
       rings for example */
    struct timespec queryRealTime;
    struct timespec now;
    gettime(&now);
    gettime(&queryRealTime, true);
    char* query = (char*) du->query.c_str();

    struct dnsheader* dh = reinterpret_cast<struct dnsheader*>((char*)query);
    uint16_t len = du->query.length();

    if (!checkQueryHeaders(dh)) {
      return; 
    }

    string poolname;
    int delayMsec = 0;
    const uint16_t * flags = getFlagsFromDNSHeader(dh);
    const uint16_t origFlags = *flags;
    uint16_t qtype, qclass;
    unsigned int consumed = 0;
    DNSName qname(query, len, sizeof(dnsheader), false, &qtype, &qclass, &consumed);
    DNSQuestion dq(&qname, qtype, qclass, &du->dest, &du->remote, dh, 1500, len, false, &queryRealTime);
    queryId = ntohs(dh->id);
    if (!processQuery(holders, dq, poolname, &delayMsec, now))
    {
      return;
    }

    if(dq.dh->qr) { // something turned it into a response
      restoreFlags(dh, origFlags);

      if (!cs.muted) {
        char* response = query;
        uint16_t responseLen = dq.len;

        DNSResponse dr(dq.qname, dq.qtype, dq.qclass, dq.local, dq.remote, reinterpret_cast<dnsheader*>(response), dq.size, responseLen, false, &queryRealTime);
#ifdef HAVE_PROTOBUF
        dr.uniqueId = dq.uniqueId;
#endif
        dr.qTag = dq.qTag;

        if (!processResponse(holders.selfAnsweredRespRulactions, dr, &delayMsec)) {
          return;
        }

        //        sendUDPResponse(cs.udpFD, response, responseLen, delayMsec, dest, remote);
        // actually do sendDOHResponse

        g_stats.selfAnswered++;
        doLatencyStats(0);  // we're not going to measure this
      }

      return;
    }

    DownstreamState* ss = nullptr;
    std::shared_ptr<ServerPool> serverPool = getPool(*holders.pools, poolname);
    std::shared_ptr<DNSDistPacketCache> packetCache = serverPool->packetCache;
    auto policy = *(holders.policy);
    if (serverPool->policy != nullptr) {
      policy = *(serverPool->policy);
    }
    auto servers = serverPool->getServers();
    if (policy.isLua) {
      std::lock_guard<std::mutex> lock(g_luamutex);
      ss = policy.policy(servers, &dq).get();
    }
    else {
      ss = policy.policy(servers, &dq).get();
    }

    bool ednsAdded = false;
    bool ecsAdded = false;
    if (dq.useECS && ((ss && ss->useECS) || (!ss && serverPool->getECS()))) {
      if (!handleEDNSClientSubnet(query, dq.size, consumed, &dq.len, &(ednsAdded), &(ecsAdded), du->remote, dq.ecsOverride, dq.ecsPrefixLength)) {
        vinfolog("Dropping query from %s because we couldn't insert the ECS value", du->remote.toStringWithPort());
        return;
      }
    }

    uint32_t cacheKey = 0;
    if (packetCache && !dq.skipCache) {
      uint16_t cachedResponseSize = dq.size;
      uint32_t allowExpired = ss ? 0 : g_staleCacheEntriesTTL;
      if (packetCache->get(dq, consumed, dh->id, query, &cachedResponseSize, &cacheKey, allowExpired)) {
        DNSResponse dr(dq.qname, dq.qtype, dq.qclass, dq.local, dq.remote, reinterpret_cast<dnsheader*>(query), dq.size, cachedResponseSize, false, &queryRealTime);
#ifdef HAVE_PROTOBUF
        dr.uniqueId = dq.uniqueId;
#endif
        dr.qTag = dq.qTag;

        if (!processResponse(holders.cacheHitRespRulactions, dr, &delayMsec)) {
          return;
        }

        if (!cs.muted) {
          // sendUDPResponse(cs.udpFD, query, cachedResponseSize, delayMsec, dest, remote);
          // XXXX actually send DOH response
        }

        g_stats.cacheHits++;
        doLatencyStats(0);  // we're not going to measure this
        return;
      }
      g_stats.cacheMisses++;
    }

    if(!ss) {
      g_stats.noPolicy++;

      if (g_servFailOnNoPolicy && !cs.muted) {
        char* response = query;
        uint16_t responseLen = dq.len;
        restoreFlags(dh, origFlags);

        dq.dh->rcode = RCode::ServFail;
        dq.dh->qr = true;

        DNSResponse dr(dq.qname, dq.qtype, dq.qclass, dq.local, dq.remote, reinterpret_cast<dnsheader*>(response), dq.size, responseLen, false, &queryRealTime);
#ifdef HAVE_PROTOBUF
        dr.uniqueId = dq.uniqueId;
#endif
        dr.qTag = dq.qTag;

        if (!processResponse(holders.selfAnsweredRespRulactions, dr, &delayMsec)) {
          return;
        }

        //        sendUDPResponse(cs.udpFD, response, responseLen, 0, dest, remote);
        // XXXX actually sendDOHResponse

        // no response-only statistics counter to update.
        doLatencyStats(0);  // we're not going to measure this
      }
      vinfolog("%s query for %s|%s from %s, no policy applied", g_servFailOnNoPolicy ? "ServFailed" : "Dropped", dq.qname->toString(), QType(dq.qtype).getName(), du->remote.toStringWithPort());
      return;
    }

    if (dq.addXPF && ss->xpfRRCode != 0) {
      addXPF(dq, ss->xpfRRCode);
    }

    ss->queries++;

    unsigned int idOffset = (ss->idOffset++) % ss->idStates.size();
    IDState* ids = &ss->idStates[idOffset];
    ids->age = 0;
    ids->du = du;
    if(ids->origFD < 0) // if we are reusing, no change in outstanding
      ss->outstanding++;
    else {
      ss->reuseds++;
      g_stats.downstreamTimeouts++;
    }

    ids->cs = &cs;
    ids->origFD = cs.udpFD;
    ids->origID = dh->id;
    ids->origRemote = du->remote;
    ids->sentTime.set(queryRealTime);
    ids->qname = qname;
    ids->qtype = dq.qtype;
    ids->qclass = dq.qclass;
    ids->delayMsec = delayMsec;
    ids->tempFailureTTL = dq.tempFailureTTL;
    ids->origFlags = origFlags;
    ids->cacheKey = cacheKey;
    ids->skipCache = dq.skipCache;
    ids->packetCache = packetCache;
    ids->ednsAdded = ednsAdded;
    ids->ecsAdded = ecsAdded;
    ids->qTag = dq.qTag;

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

#ifdef HAVE_PROTOBUF
    ids->uniqueId = dq.uniqueId;
#endif

    dh->id = idOffset;

    int fd = pickBackendSocketForSending(ss);
    ssize_t ret = udpClientSendRequestToBackend(ss, fd, query, dq.len);

    if(ret < 0) {
      ss->sendErrors++;
      g_stats.downstreamSendErrors++;
    }

    vinfolog("Got query for %s|%s from %s, relayed to %s", ids->qname.toString(), QType(ids->qtype).getName(), du->remote.toStringWithPort(), ss->getName());
  }
  catch(const std::exception& e){
    vinfolog("Got an error in UDP question thread while parsing a query from %s, id %d: %s", du->remote.toStringWithPort(), queryId, e.what());
  }
}


static h2o_pathconf_t *register_handler(h2o_hostconf_t *hostconf, const char *path, int (*on_req)(h2o_handler_t *, h2o_req_t *))
{
    h2o_pathconf_t *pathconf = h2o_config_register_path(hostconf, path, 0);
    h2o_handler_t *handler = h2o_create_handler(pathconf, sizeof(*handler));
    handler->on_req = on_req;
    return pathconf;
}


/*
   For GET, the base64url-encoded payload is in the 'dns' parameter, which might be the first parameter, or not.
   For POST, the payload is the payload.
 */
static int doh_handler(h2o_handler_t *self, h2o_req_t *req)
{
  if(!req->conn->ctx->storage.size) {
    cout<<"Did not get connection metadata!"<<endl;
    return 0;
  }
  DOHServerConfig* dsc = (DOHServerConfig*)req->conn->ctx->storage.entries[0].data;
  /*
  // print headers
  for (unsigned int i = 0; i != req->headers.size; ++i)
    printf("%.*s: %.*s\n", (int)req->headers.entries[i].name->len, req->headers.entries[i].name->base, (int)req->headers.entries[i].value.len, req->headers.entries[i].value.base);
  */
  if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("POST"))) {
    DOHUnit* du = new DOHUnit;
    uint16_t qtype;
    DNSName qname(req->entity.base, req->entity.len, sizeof(dnsheader), false, &qtype);
    cout<<(void*)req<<", POST qname: "<<qname<<", qtype: "<<qtype<<endl;
    du->req=req;
    du->query=std::string(req->entity.base, req->entity.len);

    du->rsock=dsc->dohresponsepair[0];
    du->qtype = qtype;
    if(send(dsc->dohquerypair[0], &du, sizeof(du), 0) != sizeof(du))
      delete du;     // XXX but now what - will h2o time this out for us?
  }
  else if(req->query_at != SIZE_MAX && (req->path.len - req->query_at > 4)) {
    //    if (h2o_memis(&req->path.base[req->query_at], 5, "?dns=", 5)) {

    // this should do a better job and deal with ?dns= and &dns= XXX
    char* dns = strstr(req->path.base+req->query_at, "dns=");
    if(dns) {
      dns+=4;
      if(auto p = strchr(dns, ' '))
        *p=0;
      cout<<"Got a GET dns query: "<<dns<<endl;
      // need to base64url decode this
      string sdns(dns);
      boost::replace_all(sdns,"-", "+");
      boost::replace_all(sdns,"_", "/");

      string decoded;
      if(B64Decode(sdns, decoded) < 0) {
        cout<<"Failed to decode"<<endl;
      }
      else {
        DOHUnit* du = new DOHUnit;
        uint16_t qtype;
        DNSName qname(decoded.c_str(), decoded.size(), sizeof(dnsheader), false, &qtype);
        cout<<"qname: "<<qname<<", qtype: "<<qtype<<endl;
        du->req=req;
        du->query=decoded;
        du->rsock=dsc->dohresponsepair[0];
        du->qtype = qtype;
        if(send(dsc->dohquerypair[0], &du, sizeof(du), 0) != sizeof(du))
          delete du; // XXX but now what 
      }
    }
  }
  else
    cerr<<"Some unknown request, not POST, not properly formatted GET"<<endl;
  return 0;
}


void dnsdistclient(int qsock, int rsock)
{
  for(;;) {
    DOHUnit* du;
    recv(qsock, &du, sizeof(du), 0);
    processDOHQuery(du);  // this could send out an actual response, or queue it for dnsdist
  }
}

// called if h2o finds that dnsdist gave us an answer
static void on_dnsdist(h2o_socket_t *listener, const char *err)
{
  DOHUnit *du;
  DOHServerConfig* dsc = (DOHServerConfig*)listener->data;
  recv(dsc->dohresponsepair[1], &du, sizeof(du), 0);

  du->req->res.status = 200;
  du->req->res.reason = "OK";
  
  h2o_add_header(&du->req->pool, &du->req->res.headers, H2O_TOKEN_CONTENT_TYPE, NULL, H2O_STRLIT("application/dns-message"));
  //  h2o_add_header(&du->req->pool, &du->req->res.headers, H2O_TOKEN_SET_COOKIE, NULL, H2O_STRLIT("cookie=1")); 
  
  struct dnsheader* dh = (struct dnsheader*)du->query.c_str();
  cout<<"Attempt to send out "<<du->query.size()<<" bytes over https, TC="<<dh->tc<<", RCODE="<<dh->rcode<<", qtype="<<du->qtype<<", req="<<(void*)du->req<<endl;
  
  du->req->res.content_length = du->query.size();
  h2o_send_inline(du->req, du->query.c_str(), du->query.size());
  delete du;
}

static void on_accept(h2o_socket_t *listener, const char *err)
{
  cout<<"New accept: "<< listener->data << endl;
  DOHServerConfig* dsc = (DOHServerConfig*)listener->data;
  h2o_socket_t *sock;

  if (err != NULL) {
    return;
  }
  // do some dnsdist rules here to filter based on IP address
  if ((sock = h2o_evloop_socket_accept(listener)) == NULL)
    return;

  sock->data = dsc;
  h2o_accept(&dsc->h2o_accept_ctx, sock);
}

static int create_listener(const ComboAddress& addr, DOHServerConfig* dsc)
{
  cout<<"Launching DOH listener on "<<addr.toStringWithPort()<<endl;
  int fd, reuseaddr_flag = 1;
  h2o_socket_t *sock;
  
  if ((fd = socket(addr.sin4.sin_family, SOCK_STREAM, 0)) == -1 ||
      setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_flag, sizeof(reuseaddr_flag)) != 0 ||
      bind(fd, (struct sockaddr *)&addr, addr.getSocklen()) != 0 || listen(fd, SOMAXCONN) != 0) {
    return -1;
  }
  
  sock = h2o_evloop_socket_create(dsc->h2o_ctx.loop, fd, H2O_SOCKET_FLAG_DONT_READ);
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
    dsc->h2o_accept_ctx.expect_proxy_line = 0; // makes valgrind happy
    SSL_CTX_set_options(dsc->h2o_accept_ctx.ssl_ctx, SSL_OP_NO_SSLv2);

#ifdef SSL_CTX_set_ecdh_auto
    SSL_CTX_set_ecdh_auto(dsc->h2o_accept_ctx.ssl_ctx, 1);
#endif

    /* load certificate and private key */
    if (SSL_CTX_use_certificate_file(dsc->h2o_accept_ctx.ssl_ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
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

    /* setup protocol negotiation methods */ // I have no idea what this means
#if H2O_USE_NPN
    h2o_ssl_register_npn_protocols(dsc->h2o_accept_ctx.ssl_ctx, h2o_http2_npn_protocols);
#endif
#if H2O_USE_ALPN
    h2o_ssl_register_alpn_protocols(dsc->h2o_accept_ctx.ssl_ctx, h2o_http2_alpn_protocols);
#endif

    return 0;
}

// this is the entrypoint from dnsdist.cc
int dohThread(const ComboAddress ca, vector<string> urls,  string certfile, string keyfile)
{
  auto dsc = new DOHServerConfig;
  if(socketpair(AF_LOCAL, SOCK_DGRAM, 0, dsc->dohquerypair) < 0 ||
     socketpair(AF_LOCAL, SOCK_DGRAM, 0, dsc->dohresponsepair) < 0
     ) {
    unixDie("Creating a socket pair for DNS over HTTPS");
  }

  std::thread dnsdistThread(dnsdistclient, dsc->dohquerypair[1], dsc->dohresponsepair[0]);

  //  h2o_access_log_filehandle_t *logfh = h2o_access_log_open_handle("/dev/stdout", NULL, H2O_LOGCONF_ESCAPE_APACHE);

  
  h2o_config_init(&dsc->h2o_config);

  // I wonder if this registers an IP address.. I think it does
  // this may mean we need to actually register a site "name" here and not the IP address
  h2o_hostconf_t *hostconf = h2o_config_register_host(&dsc->h2o_config, h2o_iovec_init(ca.toString().c_str(), ca.toString().size()), 65535);

  for(const auto& url : urls) {
    cout<<"Registering URL prefix "<< url << " for " <<ca.toStringWithPort() << endl;
    //    h2o_pathconf_t *pathconf;
    /* pathconf = */ register_handler(hostconf, url.c_str(), doh_handler);
    
    //    if (logfh != NULL)
    //  h2o_access_log_register(pathconf, logfh);
  }
  
  h2o_context_init(&dsc->h2o_ctx, h2o_evloop_create(), &dsc->h2o_config);

  // in this ugly way we insert the DOHServerConfig pointer in there
  h2o_vector_reserve(NULL, &dsc->h2o_ctx.storage, 1);
  dsc->h2o_ctx.storage.entries[0].data = (void*)dsc;
  ++dsc->h2o_ctx.storage.size;
  

  auto sock = h2o_evloop_socket_create(dsc->h2o_ctx.loop, dsc->dohresponsepair[1], H2O_SOCKET_FLAG_DONT_READ);
  sock->data = dsc;

  // this listens to responses from dnsdist to turn into http responses
  h2o_socket_read_start(sock, on_dnsdist);

  // we should probably make that hash, algorithm etc line configurable too 
  if(setup_ssl(dsc, certfile.c_str(), keyfile.c_str(), 
                "DEFAULT:!MD5:!DSS:!DES:!RC4:!RC2:!SEED:!IDEA:!NULL:!ADH:!EXP:!SRP:!PSK") != 0)
    goto Error;

  // as one does
  dsc->h2o_accept_ctx.ctx = &dsc->h2o_ctx;
  dsc->h2o_accept_ctx.hosts = dsc->h2o_config.hosts;

  if (create_listener(ca, dsc) != 0) {
    // should take down dnsdist
    fprintf(stderr, "failed to listen to %s: %s\n", ca.toStringWithPort().c_str(), strerror(errno));
    goto Error;
  }
  
  while (h2o_evloop_run(dsc->h2o_ctx.loop, INT32_MAX) == 0)
    ;
  
 Error:
  return 1;
}
