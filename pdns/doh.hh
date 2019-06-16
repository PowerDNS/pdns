#pragma once
#include "iputils.hh"

struct DOHServerConfig;

struct DOHFrontend
{
  std::shared_ptr<DOHServerConfig> d_dsc{nullptr};
  std::vector<std::pair<std::string, std::string>> d_certKeyPairs;
  std::string d_ciphers;
  std::string d_ciphers13;
  std::string d_serverTokens{"h2o/dnsdist"};
  std::set<std::pair<std::string, std::string>> d_customResponseHeaders;
  ComboAddress d_local;

  uint32_t d_idleTimeout{30};             // HTTP idle timeout in seconds
  std::vector<std::string> d_urls;

  std::atomic<uint64_t> d_httpconnects;   // number of TCP/IP connections established
  std::atomic<uint64_t> d_http1queries;   // valid DNS queries received via HTTP1
  std::atomic<uint64_t> d_http2queries;   // valid DNS queries received via HTTP2
  std::atomic<uint64_t> d_tls10queries;   // valid DNS queries received via TLSv1.0
  std::atomic<uint64_t> d_tls11queries;   // valid DNS queries received via TLSv1.1
  std::atomic<uint64_t> d_tls12queries;   // valid DNS queries received via TLSv1.2
  std::atomic<uint64_t> d_tls13queries;   // valid DNS queries received via TLSv1.3
  std::atomic<uint64_t> d_tlsUnknownqueries;   // valid DNS queries received via unknown TLS version

  std::atomic<uint64_t> d_getqueries;     // valid DNS queries received via GET
  std::atomic<uint64_t> d_postqueries;    // valid DNS queries received via POST
  std::atomic<uint64_t> d_badrequests;     // request could not be converted to dns query
  std::atomic<uint64_t> d_errorresponses; // dnsdist set 'error' on response
  std::atomic<uint64_t> d_validresponses; // valid responses sent out

#ifndef HAVE_DNS_OVER_HTTPS
  void setup()
  {
  }

  void reloadCertificates()
  {
  }
#else
  void setup();
  void reloadCertificates();
#endif /* HAVE_DNS_OVER_HTTPS */
};

#ifndef HAVE_DNS_OVER_HTTPS
struct DOHUnit
{
};

#else /* HAVE_DNS_OVER_HTTPS */
struct st_h2o_req_t;

struct DOHUnit
{
  std::string query;
  ComboAddress remote;
  ComboAddress dest;
  st_h2o_req_t* req{nullptr};
  DOHUnit** self{nullptr};
  int rsock;
  uint16_t qtype;
  bool error{false};
  bool ednsAdded{false};
};

#endif /* HAVE_DNS_OVER_HTTPS  */
