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
  std::vector<DNSZoneRecord>::iterator first;
  std::vector<DNSZoneRecord>::iterator second;

  // We assume the CNAMES are listed first in the ANSWER section and the other records
  // and we want to shuffle the other records only

  // First we scan for the first non-CNAME ANSWER record
  for (first = rrs.begin(); first != rrs.end(); ++first) {
    if (first->dr.d_place == DNSResourceRecord::ANSWER && first->dr.d_type != QType::CNAME) {
      break;
    }
  }
  // And then for one past the last ANSWER record
  for (second = first; second != rrs.end(); ++second) {
    if (second->dr.d_place != DNSResourceRecord::ANSWER) {
      break;
    }
  }

  // Now shuffle the non-CNAME ANSWER records
  dns_random_engine randomEngine;
  if (second - first > 1) {
    shuffle(first, second, randomEngine);
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
    shuffle(first, second, randomEngine);
  }
  // we don't shuffle the rest
}

// shuffle, maintaining some semblance of order
static void shuffle(std::vector<DNSRecord>& rrs, bool includingAdditionals)
{
  // This shuffles in the same style as the above method, keeping CNAME in the front and RRSIGs at the end
  std::vector<DNSRecord>::iterator first;
  std::vector<DNSRecord>::iterator second;

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

  pdns::dns_random_engine randomEngine;
  if (second - first > 1) {
    shuffle(first, second, randomEngine);
  }

  if (!includingAdditionals) {
    return;
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
    shuffle(first, second, randomEngine);
  }
  // we don't shuffle the rest
}

static uint16_t mapTypesToOrder(uint16_t type)
{
  if (type == QType::CNAME) {
    return 0;
  }
  if (type == QType::RRSIG) {
    return 65535;
  }
  return 1;
}

// make sure rrs is sorted in d_place order to avoid surprises later
// then shuffle the parts that desire shuffling
void pdns::orderAndShuffle(vector<DNSRecord>& rrs, bool includingAdditionals)
{
  std::stable_sort(rrs.begin(), rrs.end(), [](const DNSRecord& lhs, const DNSRecord& rhs) {
    return std::tuple(lhs.d_place, mapTypesToOrder(lhs.d_type)) < std::tuple(rhs.d_place, mapTypesToOrder(rhs.d_type));
  });
  shuffle(rrs, includingAdditionals);
}

unsigned int pdns::dedupRecords(vector<DNSRecord>& rrs)
{
  // This function tries to avoid unnecessary work
  // First a vector with zero or one element does not need dedupping
  if (rrs.size() <= 1) {
    return 0;
  }

  // If we have a larger vector, first check if we actually have duplicates.
  // We assume the most common case is: no
  std::unordered_set<std::string> seen;
  std::vector<bool> dups(rrs.size(), false);

  unsigned int counter = 0;
  unsigned int numDups = 0;

  seen.reserve(rrs.size());
  for (const auto& rec : rrs) {
    auto key = rec.getContent()->serialize(rec.d_name, true, true, true);
    // This ignores class, ttl and place by using constants for those
    if (!seen.emplace(std::move(key)).second) {
      dups[counter] = true;
      numDups++;
    }
    ++counter;
  }

  if (numDups == 0) {
    // Original is fine as-is.
    return 0;
  }

  // We avoid calling erase, as it calls a lot of move constructors. This can hurt, especially if
  // you call it on a large vector multiple times.
  // So we just take the elements that are unique
  std::vector<DNSRecord> ret;
  ret.reserve(rrs.size() - numDups);
  for (counter = 0; counter < rrs.size(); ++counter) {
    if (!dups[counter]) {
      ret.emplace_back(std::move(rrs[counter]));
    }
  }
  rrs = std::move(ret);
  return numDups;
}
