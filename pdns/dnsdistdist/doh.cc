#define H2O_USE_EPOLL 1
#include <errno.h>
#include <iostream>
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http2.h"
#include "base64.hh"
#include "dnsname.hh"
#undef CERT
#include "dns.hh"
#include <boost/algorithm/string.hpp>
using namespace std;

#define USE_HTTPS 1
#define USE_MEMCACHED 0

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

static int all_test(h2o_handler_t *self, h2o_req_t *req)
{
  cout<<"Called!"<<endl;
  /*
  if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("POST")) &&
      h2o_memis(req->path_normalized.base, req->path_normalized.len, H2O_STRLIT("/post-test/"))) {
  */

  if(req->query_at != SIZE_MAX && (req->path.len - req->query_at > 5)) {
    if (h2o_memis(&req->path.base[req->query_at], 5, "?dns=", 5)) {
      char* dns=req->path.base+req->query_at+5;
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
        cout<<"decoded fine"<<endl;
        uint16_t qtype;
        DNSName qname(decoded.c_str(), decoded.size(), sizeof(dnsheader), false, &qtype);
        cout<<"qname: "<<qname<<", qtype: "<<qtype<<endl;

      }
         
    }
  }
  
  static h2o_generator_t generator = {NULL, NULL};
  req->res.status = 200;
  req->res.reason = "OK";

  h2o_iovec_t body = h2o_strdup(&req->pool, "hello world\n", SIZE_MAX);

  
  h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, NULL, H2O_STRLIT("text/plain; charset=utf-8"));
  h2o_start_response(req, &generator);
  h2o_send(req, &body, 1, (h2o_send_state_t)1);

  
  //  h2o_send(req, &req->entity, 1, (h2o_send_state_t)1);
  return 0;

  /*}

          return -1;*/
}



static void on_accept(h2o_socket_t *listener, const char *err)
{
    h2o_socket_t *sock;

    if (err != NULL) {
        return;
    }

    if ((sock = h2o_evloop_socket_accept(listener)) == NULL)
        return;
    h2o_accept(&accept_ctx, sock);
}

static int create_listener(void)
{
    struct sockaddr_in addr;
    int fd, reuseaddr_flag = 1;
    h2o_socket_t *sock;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0x7f000001);
    addr.sin_port = htons(7890);

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ||
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_flag, sizeof(reuseaddr_flag)) != 0 ||
        bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, SOMAXCONN) != 0) {
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

int dohThread()
{
    h2o_hostconf_t *hostconf;
    h2o_access_log_filehandle_t *logfh = h2o_access_log_open_handle("/dev/stdout", NULL, H2O_LOGCONF_ESCAPE_APACHE);
    h2o_pathconf_t *pathconf;

    h2o_config_init(&config);
    hostconf = h2o_config_register_host(&config, h2o_iovec_init(H2O_STRLIT("127.0.0.1")), 65535);

    pathconf = register_handler(hostconf, "/", all_test);
    if (logfh != NULL)
        h2o_access_log_register(pathconf, logfh);


    h2o_context_init(&ctx, h2o_evloop_create(), &config);


    if (USE_HTTPS &&
        setup_ssl("server.crt", "server.key",
                  "DEFAULT:!MD5:!DSS:!DES:!RC4:!RC2:!SEED:!IDEA:!NULL:!ADH:!EXP:!SRP:!PSK") != 0)
        goto Error;

    accept_ctx.ctx = &ctx;
    accept_ctx.hosts = config.hosts;

    if (create_listener() != 0) {
        fprintf(stderr, "failed to listen to 127.0.0.1:7890:%s\n", strerror(errno));
        goto Error;
    }

    while (h2o_evloop_run(ctx.loop, INT32_MAX) == 0)
        ;

Error:
    return 1;
}
