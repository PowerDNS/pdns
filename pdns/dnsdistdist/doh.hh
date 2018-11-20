#pragma once
#include "iputils.hh"

struct DOHFrontend
{
  std::string d_certFile;
  std::string d_keyFile;
  ComboAddress d_local;
  std::vector<std::string> d_urls;
  std::string d_errortext;
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
};

void dohThread(std::shared_ptr<DOHFrontend> df);
