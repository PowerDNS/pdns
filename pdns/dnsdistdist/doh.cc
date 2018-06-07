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

#define USE_HTTPS 1
#define USE_MEMCACHED 0


static ClientState cs; // need to fill this in somehow
static void processDOHQuery(DOHUnit* du)
{
  LocalHolders holders;
  uint16_t queryId=0;
  try {

    cs.muted=false;
    
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


static h2o_globalconf_t config;
static h2o_context_t ctx;
static h2o_accept_ctx_t accept_ctx;

int g_dohquerypair[2];
int g_dohresponsepair[2];


/* This needs to handle 2*2 cases. {GET,POST} * {application/dns-udpwireformat, application/dns-message}
   The Content-Type can be derived from the Accept header. 

   For GET, the base64url-encoded payload is in the 'dns' parameter, which might be the first parameter, or not.
   For POST, the payload is the payload.

 */
static int doh_handler(h2o_handler_t *self, h2o_req_t *req)
{
  //  cout<<"Called: "<<req->path.base<<endl;
  if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("POST"))) {
    DOHUnit* du = new DOHUnit;
    uint16_t qtype;
    DNSName qname(req->entity.base, req->entity.len, sizeof(dnsheader), false, &qtype);
    cout<<(void*)req<<", POST qname: "<<qname<<", qtype: "<<qtype<<endl;
    du->req=req;
    du->query=std::string(req->entity.base, req->entity.len);
    du->rsock=g_dohresponsepair[0];
    du->qtype = qtype;
    send(g_dohquerypair[0], &du, sizeof(du), 0);
  }
  else if(req->query_at != SIZE_MAX && (req->path.len - req->query_at > 4)) {
    //    if (h2o_memis(&req->path.base[req->query_at], 5, "?dns=", 5)) {
    char* dns = strstr(req->path.base+req->query_at, "dns=");
    if(dns) {
      dns+=4;
      if(auto p = strchr(dns, ' '))
        *p=0;
      cout<<"Got a dns query: "<<dns<<endl;
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
        du->rsock=g_dohresponsepair[0];
        du->qtype = qtype;
        send(g_dohquerypair[0], &du, sizeof(du), 0);
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

void responsesender(int rpair[2])
{
  DOHUnit *du;
  for(;;) {
    recv(rpair[1], &du, sizeof(du), 0);
    //    cout<<"Received DU ready to https up"<<endl;
    //    static h2o_generator_t generator = {NULL, NULL};
    du->req->res.status = 200;
    du->req->res.reason = "OK";
    
    h2o_add_header(&du->req->pool, &du->req->res.headers, H2O_TOKEN_CONTENT_TYPE, NULL, H2O_STRLIT("application/dns-udpwireformat"));
    //    h2o_add_header(&du->req->pool, &du->req->res.headers, H2O_TOKEN_CONTENT_TYPE, NULL, H2O_STRLIT("application/dns-message"));
    //    h2o_start_response(du->req, &generator);
    struct dnsheader* dh = (struct dnsheader*)du->query.c_str();
    cout<<"Attempt to send out "<<du->query.size()<<" bytes over https, TC="<<dh->tc<<", RCODE="<<dh->rcode<<", qtype="<<du->qtype<<", req="<<(void*)du->req<<endl;
    du->req->res.content_length = du->query.size();
    h2o_send_inline(du->req, du->query.c_str(), du->query.size());
  }
}

static void on_accept(h2o_socket_t *listener, const char *err)
{
  cout<<"New accept"<<endl;
  h2o_socket_t *sock;

  if (err != NULL) {
    return;
  }
  
  if ((sock = h2o_evloop_socket_accept(listener)) == NULL)
    return;
  h2o_accept(&accept_ctx, sock);
}

static int create_listener(const ComboAddress& addr)
{
    int fd, reuseaddr_flag = 1;
    h2o_socket_t *sock;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ||
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_flag, sizeof(reuseaddr_flag)) != 0 ||
        bind(fd, (struct sockaddr *)&addr, addr.getSocklen()) != 0 || listen(fd, SOMAXCONN) != 0) {
        return -1;
    }

    sock = h2o_evloop_socket_create(ctx.loop, fd, H2O_SOCKET_FLAG_DONT_READ);
    h2o_socket_read_start(sock, on_accept);

    return 0;
}

static int setup_ssl(const char *cert_file, const char *key_file, const char *ciphers)
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    accept_ctx.ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_options(accept_ctx.ssl_ctx, SSL_OP_NO_SSLv2);


#ifdef SSL_CTX_set_ecdh_auto
    SSL_CTX_set_ecdh_auto(accept_ctx.ssl_ctx, 1);
#endif

    /* load certificate and private key */
    if (SSL_CTX_use_certificate_file(accept_ctx.ssl_ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "an error occurred while trying to load server certificate file:%s\n", cert_file);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(accept_ctx.ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "an error occurred while trying to load private key file:%s\n", key_file);
        return -1;
    }

    if (SSL_CTX_set_cipher_list(accept_ctx.ssl_ctx, ciphers) != 1) {
        fprintf(stderr, "ciphers could not be set: %s\n", ciphers);
        return -1;
    }

/* setup protocol negotiation methods */
#if H2O_USE_NPN
    h2o_ssl_register_npn_protocols(accept_ctx.ssl_ctx, h2o_http2_npn_protocols);
#endif
#if H2O_USE_ALPN
    h2o_ssl_register_alpn_protocols(accept_ctx.ssl_ctx, h2o_http2_alpn_protocols);
#endif

    return 0;
}

int dohThread(const ComboAddress ca, const char* certfile, const char*keyfile)
{
  if(socketpair(AF_LOCAL, SOCK_DGRAM, 0, g_dohquerypair) < 0 ||
     socketpair(AF_LOCAL, SOCK_DGRAM, 0, g_dohresponsepair) < 0
     ) {
    unixDie("Creating a socket pair for DNS over HTTPS");
  }

  std::thread dnsdistThread(dnsdistclient, g_dohquerypair[1], g_dohresponsepair[0]);
  
  std::thread responseThread(responsesender, g_dohresponsepair);
  

  h2o_access_log_filehandle_t *logfh = h2o_access_log_open_handle("/dev/stdout", NULL, H2O_LOGCONF_ESCAPE_APACHE);
  h2o_pathconf_t *pathconf;
  
  h2o_config_init(&config);
  h2o_hostconf_t *hostconf = h2o_config_register_host(&config, h2o_iovec_init(ca.toString().c_str(), ca.toString().size()), 65535);
  
  pathconf = register_handler(hostconf, "/", doh_handler);

  if (logfh != NULL)
    h2o_access_log_register(pathconf, logfh);
  
  
  h2o_context_init(&ctx, h2o_evloop_create(), &config);
  
  
  if (USE_HTTPS &&
      setup_ssl(certfile, keyfile, 
                "DEFAULT:!MD5:!DSS:!DES:!RC4:!RC2:!SEED:!IDEA:!NULL:!ADH:!EXP:!SRP:!PSK") != 0)
    goto Error;
  
  accept_ctx.ctx = &ctx;
  accept_ctx.hosts = config.hosts;


  if (create_listener(ca) != 0) {
    fprintf(stderr, "failed to listen to %s: %s\n", ca.toStringWithPort().c_str(), strerror(errno));
    goto Error;
  }
  
  while (h2o_evloop_run(ctx.loop, INT32_MAX) == 0)
    ;
  
 Error:
  return 1;
}
