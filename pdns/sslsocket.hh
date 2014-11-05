#pragma once

#include "pdns/sstuff.hh"

#include <polarssl/net.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/error.h>
#include <polarssl/ssl_cache.h>

struct SSLOptions {
  int ssl_endpoint_mode;
  int ssl_authmode;
  const int* ssl_ciphersuites;
  x509_crt* ssl_ca_chain;
  x509_crl* ssl_ca_crl;
  const char* ssl_peer_cn;
  x509_crt* ssl_own_cert;
  pk_context* ssl_own_key;
  dhm_context* ssl_dhm_ctx;
  const char *ssl_hostname;
#if defined(POLARSSL_SSL_SESSION_TICKETS)
  ssl_session ssl_session_data;
#endif

  SSLOptions() {
    memset(this, 0, sizeof(struct SSLOptions));
    ssl_authmode = SSL_VERIFY_OPTIONAL;
    ssl_ciphersuites = ssl_list_ciphersuites();
  };
};

class SSLSocket: public Socket {
protected:
  void initialize() {
    int ret;
    entropy_init(&d_entropy);
    if ((ret = ctr_drbg_init(&d_ctr_drbg, entropy_func, &d_entropy, NULL, 0)) != 0 )
    {
        ostringstream oss;
        polarssl_strerror(ret, d_buffer, d_buflen);
        oss << "ctr_drbg_init returned " << d_buffer;
        throw NetworkError(oss.str());
    }
    memset(&d_ssl, 0, sizeof(ssl_context));
    if ((ret = ssl_init(&d_ssl)) != 0)
    {
        ostringstream oss;
        polarssl_strerror(ret, d_buffer, d_buflen);
        oss << "ssl_init returned " << d_buffer;
        throw NetworkError(oss.str());
    }
    d_handshake = false;
  };

  void ssl_handshake() {
    int ret;
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    // make handshake timeout
    setsockopt(d_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
    if ((ret = ::ssl_handshake(&d_ssl)) != 0) {
      ostringstream oss;
      polarssl_strerror(ret, d_buffer, d_buflen);
      oss << "ssl_handshake returned " << d_buffer;
      throw NetworkError(oss.str());
    }
    memset(&tv,0,sizeof(struct timeval));
    setsockopt(d_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
    d_handshake = true;
  };

  int internal_recv(char *buffer, size_t buflen) {
    if (!d_handshake) ssl_handshake();
    int ret = ::ssl_read(&d_ssl, (unsigned char*)buffer, buflen);
    if (ret == POLARSSL_ERR_NET_WANT_READ) ret = EAGAIN;
    return ret;
  };

  int internal_send(const char *buffer, size_t buflen) {
    if (!d_handshake) ssl_handshake();
    int ret = ::ssl_write(&d_ssl, (const unsigned char*)buffer, buflen);
    if (ret == POLARSSL_ERR_NET_WANT_WRITE) ret = EAGAIN;
    return ret;    
  };
public:
  SSLSocket(int af, int st, ProtocolType pt=0): Socket(af, st, pt) {
    initialize(); 
  };

  ~SSLSocket() {
    ssl_free( &d_ssl );
  }

  void initSSL(const SSLOptions *opts) {
    ssl_set_endpoint(&d_ssl, opts->ssl_endpoint_mode);
    ssl_set_authmode(&d_ssl, opts->ssl_authmode);
    if (opts->ssl_ciphersuites)
      ssl_set_ciphersuites(&d_ssl, opts->ssl_ciphersuites);
//  this is only ever needed for developers
//    ssl_set_dbg( &d_ssl, &SSLSocket::polarssl_debug, this );
    if (opts->ssl_ca_chain)
      ssl_set_ca_chain(&d_ssl, opts->ssl_ca_chain, opts->ssl_ca_crl, opts->ssl_peer_cn);
    if (opts->ssl_own_cert && opts->ssl_own_key)
      ssl_set_own_cert(&d_ssl, opts->ssl_own_cert, opts->ssl_own_key);
    if (opts->ssl_dhm_ctx)
      ssl_set_dh_param_ctx(&d_ssl, opts->ssl_dhm_ctx);
    if (opts->ssl_hostname && opts->ssl_authmode == SSL_IS_CLIENT)
      ssl_set_hostname(&d_ssl, opts->ssl_hostname);

    ssl_set_rng(&d_ssl, &SSLSocket::polarssl_rng, this);
    ssl_set_bio(&d_ssl, &SSLSocket::polarssl_net_recv, this, &SSLSocket::polarssl_net_send, this);

#if defined(POLARSSL_SSL_SESSION_TICKETS)
    ssl_set_session_tickets(&d_ssl, SSL_SESSION_TICKETS_ENABLED);
    ssl_set_session(&d_ssl, &opts->ssl_session_data); 
#endif
  };

  virtual int readWithTimeout(char* buffer, int n, int timeout)
  {
    int err;
    if ((err = ssl_get_bytes_avail(&d_ssl)) < 1)
      err = waitForRWData(d_socket, true, timeout, 0);

    if(err == 0)
      throw NetworkError("timeout reading");
    if(err < 0)
      throw NetworkError("nonblocking read failed: "+string(strerror(errno)));

    return read(buffer, n);
  };

  ssl_context* getContext() { return &d_ssl; };

#if defined(POLARSSL_SSL_SESSION_TICKETS)
  ssl_session* getSession() { return getContext()->session; };
#endif

  static int polarssl_net_recv(void *param, unsigned char *buffer, size_t blen) {
    SSLSocket& ptr = *reinterpret_cast<SSLSocket*>(param);
    return ::net_recv(&ptr.d_socket, buffer, blen);
  }

  static int polarssl_net_send(void *param, const unsigned char *buffer, size_t blen) {
    SSLSocket& ptr = *reinterpret_cast<SSLSocket*>(param);
    return ::net_send(&ptr.d_socket, buffer, blen);
  }

  static int polarssl_rng(void *param, unsigned char *buffer, size_t blen) {
    SSLSocket& ptr = *reinterpret_cast<SSLSocket*>(param);
    return ::ctr_drbg_random(&ptr.d_ctr_drbg, buffer, blen);
  }

  static void polarssl_debug(void *param, int level, const char *buffer) {
    if (level<3) // spam reduce
      std::cerr<<level<<": "<<buffer;
  }

protected:
  entropy_context d_entropy;
  ctr_drbg_context d_ctr_drbg;
  ssl_context d_ssl;
  bool d_handshake;
};
