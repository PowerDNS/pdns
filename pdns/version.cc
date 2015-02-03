/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2013  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "logger.hh"
#include "version.hh"
#include "version_generated.h"
#include <polarssl/version.h>

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
  return PDNS_VERSION;
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
  theL()<<Logger::Warning<<productName()<<" "<< PDNS_VERSION <<" (" DIST_HOST ") "
    "(C) 2001-2015 PowerDNS.COM BV" << endl;
  theL()<<Logger::Warning<<"Using "<<(sizeof(unsigned long)*8)<<"-bits mode. "
    "Built on " BUILD_DATE " by " BUILD_HOST ", "<<compilerVersion()<<"."<<endl;
  theL()<<Logger::Warning<<"PowerDNS comes with ABSOLUTELY NO WARRANTY. "
    "This is free software, and you are welcome to redistribute it "
    "according to the terms of the GPL version 2." << endl;
}

void showBuildConfiguration()
{
  theL()<<Logger::Warning<<"Features: "<<
#ifdef HAVE_BOTAN110
    "botan1.10 " <<
#endif
#ifdef HAVE_BOTAN18
    "botan1.8" <<
#endif
#ifdef HAVE_CRYPTOPP
    "cryptopp " <<
#endif
#ifdef HAVE_ED25519
    "ed25519 " <<
#endif
#ifdef HAVE_LIBDL
    "libdl " <<
#endif
#ifdef HAVE_LUA
    "lua " <<
#endif
#ifdef REMOTEBACKEND_ZEROMQ
    "remotebackend-zeromq" <<
#endif
#ifdef VERBOSELOG
    "verboselog" <<
#endif
    endl;
#ifdef PDNS_MODULES
  // Auth only
  theL()<<Logger::Warning<<"Built-in modules: "<<PDNS_MODULES<<endl;
#endif
#ifndef POLARSSL_SYSTEM
  theL()<<Logger::Warning<<"Built-in PolarSSL: "<<POLARSSL_VERSION_STRING<<endl;
#endif
}

string fullVersionString()
{
  ostringstream s;
  s<<productName()<<" " PDNS_VERSION " (" DIST_HOST " built " BUILD_DATE " " BUILD_HOST ")";
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
