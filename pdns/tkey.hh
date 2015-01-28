#ifndef PDNS_TKEY_HH
#define PDNS_TKEY_HH
#pragma once

#ifdef ENABLE_GSS_TSIG
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <gssapi/gssapi_ext.h>
#endif

void pdns_tkey_handler(DNSPacket *p, DNSPacket *r);

#ifdef ENABLE_GSS_TSIG

#define PDNS_GSSAPI_OK        0
#define PDNS_GSSAPI_CONTINUE  1
#define PDNS_GSSAPI_BADKEY    2
#define PDNS_GSSAPI_BADNAME   3

// these are found in gssapi.cc
int pdns_gssapi_accept_ctx(const std::string& label, const std::string& input, std::string& output);
bool pdns_gssapi_delete_ctx(const std::string& label, const std::string& input, std::string& output);
bool pdns_gssapi_sign(const std::string& label, const std::string& input, std::string& output);
bool pdns_gssapi_verify(const std::string& label, const std::string& input, const std::string& token);
bool pdns_gssapi_match_credential(const std::string& label, const std::string& credential);
#endif

#endif
