/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "logger.hh"
#include "version.hh"

static ProductType productType;

string compilerVersion()
{
#if defined(__clang__)
  return string("clang " __clang_version__ );
#elif defined(__GNUC__)
  return string("gcc " __VERSION__ );
#else  // add other compilers here
  return string("Unknown compiler");
#endif
}

// Human-readable product name
string productName() {
  switch (productType) {
  case ProductAuthoritative:
    return "PowerDNS Authoritative Server";
  case ProductRecursor:
    return "PowerDNS Recursor";
  };
  return "Unknown";
}

string getPDNSVersion()
{
  return VERSION;
}

// REST API product type
string productTypeApiType() {
  switch (productType) {
  case ProductAuthoritative:
    return "authoritative";
  case ProductRecursor:
    return "recursor";
  };
  return "unknown";
}

void showProductVersion()
{
  g_log<<Logger::Warning<<productName()<<" "<< VERSION << " (C) 2001-2019 "
    "PowerDNS.COM BV" << endl;
  g_log<<Logger::Warning<<"Using "<<(sizeof(unsigned long)*8)<<"-bits mode. "
    "Built using " << compilerVersion()
#ifndef REPRODUCIBLE
    <<" on " __DATE__ " " __TIME__ " by " BUILD_HOST
#endif
    <<"."<< endl;
  g_log<<Logger::Warning<<"PowerDNS comes with ABSOLUTELY NO WARRANTY. "
    "This is free software, and you are welcome to redistribute it "
    "according to the terms of the GPL version 2." << endl;
}

void showBuildConfiguration()
{
  g_log<<Logger::Warning<<"Features: "<<
#ifdef HAVE_LIBDECAF
    "decaf " <<
#endif
#ifdef HAVE_BOOST_CONTEXT
    "fcontext " <<
#endif
#ifdef HAVE_LIBCRYPTO_ECDSA
    "libcrypto-ecdsa " <<
#endif
#ifdef HAVE_LIBCRYPTO_ED25519
    "libcrypto-ed25519 " <<
#endif
#ifdef HAVE_LIBCRYPTO_ED448
    "libcrypto-ed448 " <<
#endif
#ifdef HAVE_LIBCRYPTO_EDDSA
    "libcrypto-eddsa " <<
#endif
#ifdef HAVE_LIBDL
    "libdl " <<
#endif
#ifdef HAVE_GEOIP
    "libgeoip " <<
#endif
#ifdef HAVE_MMDB
    "libmaxminddb " <<
#endif
#ifdef HAVE_LUA
    "lua " <<
#endif
#ifdef HAVE_LUA_RECORDS
    "lua-records " <<
#endif
#ifdef NOD_ENABLED
    "nod " <<
#endif
#ifdef HAVE_P11KIT1
    "PKCS#11 " <<
#endif
#ifdef HAVE_PROTOBUF
"protobuf " <<
#endif
#ifdef HAVE_FSTRM
"dnstap-framestream " <<
#endif
#ifdef REMOTEBACKEND_ZEROMQ
    "remotebackend-zeromq " <<
#endif
#ifdef HAVE_NET_SNMP
    "snmp " <<
#endif
#ifdef HAVE_LIBSODIUM
    "sodium " <<
#endif
#ifdef VERBOSELOG
    "verboselog" <<
#endif
    endl;
#ifdef PDNS_MODULES
  // Auth only
  g_log<<Logger::Warning<<"Built-in modules: "<<PDNS_MODULES<<endl;
#endif
#ifdef PDNS_CONFIG_ARGS
#define double_escape(s) #s
#define escape_quotes(s) double_escape(s)
  g_log<<Logger::Warning<<"Configured with: "<<escape_quotes(PDNS_CONFIG_ARGS)<<endl;
#undef escape_quotes
#undef double_escape
#endif
}

string fullVersionString()
{
  ostringstream s;
  s<<productName()<<" " VERSION;
#ifndef REPRODUCIBLE
  s<<" (built " __DATE__ " " __TIME__ " by " BUILD_HOST ")";
#endif
  return s.str();
}

void versionSetProduct(ProductType pt)
{
  productType = pt;
}

ProductType versionGetProduct()
{
  return productType;
}
