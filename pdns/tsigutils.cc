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

#include "dnsname.hh"
#include "base64.hh"
#include "dns_random.hh"
#include "misc.hh"
#include "pdnsexception.hh"
#include "tsigutils.hh"
#include <string>

/*
 * Returns a generated Base64'd TSIG key
 *
 * Will raise a PDNSException() if algorithm is invalid
 */
std::string makeTSIGKey(const DNSName& algorithm) {
  TSIGHashEnum tsigHashEnum;
  if (!getTSIGHashEnum(algorithm, tsigHashEnum)) {
    throw PDNSException("Invalid TSIG algorithm: " + algorithm.toStringNoDot());
  }

  size_t klen = 64;
  if (tsigHashEnum == TSIG_MD5
      || tsigHashEnum == TSIG_SHA1
      || tsigHashEnum == TSIG_SHA224) {
    klen = 32;
  }

  string tmpkey;
  tmpkey.resize(klen);

  // Fill out the key
  for (size_t i = 0; i < klen; i += sizeof(uint32_t)) {
    uint32_t t = dns_random(std::numeric_limits<uint32_t>::max());
    memcpy(&tmpkey.at(i), &t, sizeof(uint32_t));
  }

  return Base64Encode(tmpkey);
}
