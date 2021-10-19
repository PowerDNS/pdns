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
#include "dns.hh"
#include <iostream>
#include <string>
#include <vector>
#include <utility>
#include <sstream>
#include "qtype.hh"
#include "misc.hh"

static_assert(sizeof(QType) == 2, "QType is not 2 bytes in size, something is wrong!");

const map<const string, uint16_t> QType::names = {
  {"A", 1},
  {"NS", 2},
  {"CNAME", 5},
  {"SOA", 6},
  {"MB", 7},
  {"MG", 8},
  {"MR", 9},
  {"PTR", 12},
  {"HINFO", 13},
  {"MINFO", 14},
  {"MX", 15},
  {"TXT", 16},
  {"RP", 17},
  {"AFSDB", 18},
  {"SIG", 24},
  {"KEY", 25},
  {"AAAA", 28},
  {"LOC", 29},
  {"SRV", 33},
  {"NAPTR", 35},
  {"KX", 36},
  {"CERT", 37},
  {"A6", 38},
  {"DNAME", 39},
  {"OPT", 41},
  {"APL", 42},
  {"DS", 43},
  {"SSHFP", 44},
  {"IPSECKEY", 45},
  {"RRSIG", 46},
  {"NSEC", 47},
  {"DNSKEY", 48},
  {"DHCID", 49},
  {"NSEC3", 50},
  {"NSEC3PARAM", 51},
  {"TLSA", 52},
  {"SMIMEA", 53},
  {"RKEY", 57},
  {"CDS", 59},
  {"CDNSKEY", 60},
  {"OPENPGPKEY", 61},
  {"CSYNC", 62},
  {"SVCB", 64},
  {"HTTPS", 65},
  {"SPF", 99},
  {"NID", 104},
  {"L32", 105},
  {"L64", 106},
  {"LP", 107},
  {"EUI48", 108},
  {"EUI64", 109},
  {"TKEY", 249},
  //      {"TSIG", 250},
  {"IXFR", 251},
  {"AXFR", 252},
  {"MAILB", 253},
  {"MAILA", 254},
  {"ANY", 255},
  {"URI", 256},
  {"CAA", 257},
  {"DLV", 32769},
  {"ADDR", 65400},
  {"ALIAS", 65401},
  {"LUA", 65402},
};

static map<uint16_t, const string> swapElements(const map<const string, uint16_t>& names) {
  map<uint16_t, const string> ret;

  for (const auto& n : names) {
    ret.emplace(n.second, n.first);
  }
  return ret;
}

const map<uint16_t, const string> QType::numbers = swapElements(names);


bool QType::isSupportedType() const
{
  return numbers.count(code) == 1;
}

bool QType::isMetadataType() const
{
  if (code == QType::AXFR ||
      code == QType::MAILA ||
      code == QType::MAILB ||
      code == QType::TSIG ||
      code == QType::IXFR)
    return true;

  return false;
}

const string QType::toString() const
{
  const auto& name = numbers.find(code);
  if (name != numbers.cend()) {
    return name->second;
  }
  return "TYPE" + itoa(code);
}

uint16_t QType::chartocode(const char *p)
{
  string P = toUpper(p);

  const auto& num = names.find(P);
  if (num != names.cend()) {
    return num->second;
  }
  if (*p == '#') {
    return static_cast<uint16_t>(atoi(p + 1));
  }

  if (boost::starts_with(P, "TYPE")) {
    return static_cast<uint16_t>(atoi(p + 4));
  }

  return 0;
}

QType &QType::operator=(const char *p)
{
  code = chartocode(p);
  return *this;
}

QType &QType::operator=(const string &s)
{
  code = chartocode(s.c_str());
  return *this;
}

const std::string QClass::toString() const
{
  switch (qclass) {
  case IN:
    return "IN";
  case CHAOS:
    return "CHAOS";
  case NONE:
    return "NONE";
  case ANY:
    return "ANY";
  default :
    return "CLASS" + std::to_string(qclass);
  }
}
