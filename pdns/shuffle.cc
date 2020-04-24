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

#include <string>

#include "shuffle.hh"
#include "dns_random.hh"
#include "dnsparser.hh"

// shuffle, maintaining some semblance of order
void pdns::shuffle(std::vector<DNSZoneRecord>& rrs)
{
  std::vector<DNSZoneRecord>::iterator first, second;

  // We assume the CNAMES are listed firts in the ANSWWER section and the the other records
  // and we want to shuffle the other records only

  // First we scan for the first non-CNAME ANSWER record
  for (first = rrs.begin(); first != rrs.end(); ++first) {
    if (first->dr.d_place == DNSResourceRecord::ANSWER && first->dr.d_type != QType::CNAME) {
      break;
    }
  }
  // And then for one past the last ANSWER recordd
  for (second = first; second != rrs.end(); ++second)
    if (second->dr.d_place != DNSResourceRecord::ANSWER)
      break;

  // Now shuffle the non-CNAME ANSWER records
  dns_random_engine r;
  if (second - first > 1) {
    shuffle(first, second, r);
  }

  // now shuffle the ADDITIONAL records in the same manner as the ANSWER records
  for (first = second; first != rrs.end(); ++first) {
    if (first->dr.d_place == DNSResourceRecord::ADDITIONAL && first->dr.d_type != QType::CNAME) {
      break;
    }
  }
  for (second = first; second != rrs.end(); ++second) {
    if (second->dr.d_place != DNSResourceRecord::ADDITIONAL) {
      break;
    }
  }

  if (second - first > 1) {
    shuffle(first, second, r);
  }
  // we don't shuffle the rest
}

// shuffle, maintaining some semblance of order
static void shuffle(std::vector<DNSRecord>& rrs)
{
  // This shuffles in the same style as the above method, keeping CNAME in the front and RRSIGs at the end
  std::vector<DNSRecord>::iterator first, second;
  for (first = rrs.begin(); first != rrs.end(); ++first) {
    if (first->d_place == DNSResourceRecord::ANSWER && first->d_type != QType::CNAME) {
      break;
    }
  }
  for (second = first; second != rrs.end(); ++second) {
    if (second->d_place != DNSResourceRecord::ANSWER || second->d_type == QType::RRSIG) {
      break;
    }
  }

  pdns::dns_random_engine r;
  if (second - first > 1) {
    shuffle(first, second, r);
  }

  // now shuffle the additional records
  for (first = second; first != rrs.end(); ++first) {
    if (first->d_place == DNSResourceRecord::ADDITIONAL && first->d_type != QType::CNAME) {
      break;
    }
  }
  for (second = first; second != rrs.end(); ++second) {
    if (second->d_place != DNSResourceRecord::ADDITIONAL) {
      break;
    }
  }

  if (second - first > 1) {
    shuffle(first, second, r);
  }
  // we don't shuffle the rest
}

static uint16_t mapTypesToOrder(uint16_t type)
{
  if (type == QType::CNAME)
    return 0;
  if (type == QType::RRSIG)
    return 65535;
  else
    return 1;
}

// make sure rrs is sorted in d_place order to avoid surprises later
// then shuffle the parts that desire shuffling
void pdns::orderAndShuffle(vector<DNSRecord>& rrs)
{
  std::stable_sort(rrs.begin(), rrs.end(), [](const DNSRecord& a, const DNSRecord& b) {
    return std::make_tuple(a.d_place, mapTypesToOrder(a.d_type)) < std::make_tuple(b.d_place, mapTypesToOrder(b.d_type));
  });
  shuffle(rrs);
}
