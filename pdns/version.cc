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

#include "config.h"
#include "version.hh"
#include "namespaces.hh"

#ifdef PDNS_MODULES
#include "dnsbackend.hh"
#endif

#include <sstream>
#include <boost/algorithm/string/join.hpp>

static ProductType productType;

string compilerVersion()
{
#if defined(__clang__)
  return "clang " __clang_version__;
#elif defined(__GNUC__)
  return "gcc " __VERSION__;
#else // add other compilers here
  return "Unknown compiler";
#endif
}

// Human-readable product name
string productName()
{
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
string productTypeApiType()
{
  switch (productType) {
  case ProductAuthoritative:
    return "authoritative";
  case ProductRecursor:
    return "recursor";
  };
  return "unknown";
}

vector<string> getProductVersionLines()
{
  vector<string> ret;
  std::istringstream istr(getProductVersion());
  for (string line; std::getline(istr, line);) {
    ret.emplace_back(line);
  }
  return ret;
}

string getProductVersion()
{
  ostringstream ret;
  ret << productName() << " " << VERSION << " (C) "
                                            "PowerDNS.COM BV"
      << endl;
  ret << "Using " << (sizeof(unsigned long) * 8) << "-bits mode. "
                                                    "Built using "
      << compilerVersion()
#ifndef REPRODUCIBLE
      << " on " __DATE__ " " __TIME__ " by " BUILD_HOST
#endif
      << "." << endl;
  ret << "PowerDNS comes with ABSOLUTELY NO WARRANTY. "
         "This is free software, and you are welcome to redistribute it "
         "according to the terms of the GPL version 2."
      << endl;
  return ret.str();
}

string getBuildConfiguration()
{
  ostringstream ret;
  ret << "Features:"
#ifdef HAVE_LIBCRYPTO_ECDSA
      << " libcrypto-ecdsa"
#endif
#ifdef HAVE_LIBCRYPTO_ED25519
      << " libcrypto-ed25519"
#endif
#ifdef HAVE_LIBCRYPTO_ED448
      << " libcrypto-ed448"
#endif
#ifdef HAVE_LIBCRYPTO_EDDSA
      << " libcrypto-eddsa"
#endif
#ifdef HAVE_LIBDL
      << " libdl"
#endif
#ifdef HAVE_GEOIP
      << " libgeoip"
#endif
#ifdef HAVE_MMDB
      << " libmaxminddb"
#endif
#ifdef HAVE_LUA
      << " lua"
#endif
#ifdef HAVE_LUA_RECORDS
      << " lua-records"
#endif
#ifdef NOD_ENABLED
      << " nod"
#endif
#ifdef HAVE_P11KIT1
      << " PKCS#11"
#endif
      << " protobuf"
#ifdef HAVE_FSTRM
      << " dnstap-framestream"
#endif
#ifdef REMOTEBACKEND_ZEROMQ
      << " remotebackend-zeromq"
#endif
#ifdef HAVE_NET_SNMP
      << " snmp"
#endif
#ifdef HAVE_LIBSODIUM
      << " sodium"
#endif
#ifdef HAVE_LIBSSL
      << " libssl"
#endif
#ifdef HAVE_GNUTLS
      << " gnutls"
#endif
#ifdef HAVE_LIBCURL
      << " curl"
#endif
#ifdef HAVE_DNS_OVER_TLS
      << " DoT"
#endif
#ifdef HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT
      << " scrypt"
#endif
#ifdef ENABLE_GSS_TSIG
      << " gss-tsig"
#endif
#ifdef VERBOSELOG
      << " verboselog"
#endif
#ifdef HAVE_LIBCAP
      << " libcap"
#endif
      << endl;
#ifdef PDNS_MODULES
  // Auth only
  ret << "Built-in modules: " << PDNS_MODULES << endl;
  const auto& modules = BackendMakers().getModules();
  ret << "Loaded modules: " << boost::join(modules, " ") << endl;
#endif
// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#ifdef PDNS_CONFIG_ARGS
#define double_escape(s) #s
#define escape_quotes(s) double_escape(s)
  // NOLINTEND(cppcoreguidelines-macro-usage)
  ret << "Configured with: " << escape_quotes(PDNS_CONFIG_ARGS) << endl;
#undef escape_quotes
#undef double_escape
#endif
  return ret.str();
}

string fullVersionString()
{
  ostringstream ret;
  ret << productName() << " " VERSION;
#ifndef REPRODUCIBLE
  ret << " (built " __DATE__ " " __TIME__ " by " BUILD_HOST ")";
#endif
  return ret.str();
}

void versionSetProduct(ProductType productType_)
{
  productType = productType_;
}

ProductType versionGetProduct()
{
  return productType;
}
