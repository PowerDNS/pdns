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
// these are found in gssapi.cc
gss_ctx_id_t pdns_gssapi_find_ctx(const std::string& label);
OM_uint32 pdns_gssapi_accept_ctx(const std::string& label, const std::string& input, std::string& output);
bool pdns_gssapi_delete_ctx(const std::string& label, const std::string& input, std::string& output);
#endif

#endif
