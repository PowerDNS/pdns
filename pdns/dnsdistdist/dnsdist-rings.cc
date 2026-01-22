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

#include <fstream>

#include "dnsdist-rings.hh"

void Rings::init(const RingsConfiguration& config)
{
  if (d_initialized.exchange(true)) {
    throw std::runtime_error("Rings::init() should only be called once");
  }

  d_capacity = config.capacity;
  d_numberOfShards = config.numberOfShards;
  d_nbLockTries = config.nbLockTries;
  d_samplingRate = config.samplingRate;
  d_recordQueries = config.recordQueries;
  d_recordResponses = config.recordResponses;
  if (d_numberOfShards <= 1) {
    d_nbLockTries = 0;
  }

  d_shards.resize(d_numberOfShards);

  /* resize all the rings */
  for (auto& shard : d_shards) {
    shard = std::make_unique<Shard>();
    if (shouldRecordQueries()) {
      shard->queryRing.lock()->set_capacity(d_capacity / d_numberOfShards);
    }
    if (shouldRecordResponses()) {
      shard->respRing.lock()->set_capacity(d_capacity / d_numberOfShards);
    }
  }

  /* we just recreated the shards so they are now empty */
  d_nbQueryEntries = 0;
  d_nbResponseEntries = 0;
}

size_t Rings::numDistinctRequestors()
{
  std::set<ComboAddress, ComboAddress::addressOnlyLessThan> requestors;
  for (const auto& shard : d_shards) {
    auto queries = shard->queryRing.lock();
    for (const auto& query : *queries) {
      requestors.insert(query.requestor);
    }
  }
  return requestors.size();
}

std::unordered_map<int, vector<boost::variant<string, double>>> Rings::getTopBandwidth(unsigned int numentries)
{
  map<ComboAddress, unsigned int, ComboAddress::addressOnlyLessThan> counts;
  uint64_t total = 0;
  for (const auto& shard : d_shards) {
    {
      auto queries = shard->queryRing.lock();
      for (const auto& query : *queries) {
        counts[query.requestor] += query.size;
        total += query.size;
      }
    }
    {
      auto responses = shard->respRing.lock();
      for (const auto& response : *responses) {
        counts[response.requestor] += response.size;
        total += response.size;
      }
    }
  }

  using ret_t = vector<pair<unsigned int, ComboAddress>>;
  ret_t rcounts;
  rcounts.reserve(counts.size());
  for (const auto& count : counts) {
    rcounts.emplace_back(count.second, count.first);
  }
  numentries = rcounts.size() < numentries ? rcounts.size() : numentries;
  partial_sort(rcounts.begin(), rcounts.begin() + numentries, rcounts.end(), [](const ret_t::value_type& lhs, const ret_t::value_type& rhs) {
    return (rhs.first < lhs.first);
  });
  std::unordered_map<int, vector<boost::variant<string, double>>> ret;
  uint64_t rest = 0;
  int count = 1;
  for (const auto& rcount : rcounts) {
    if (count == static_cast<int>(numentries + 1)) {
      rest += rcount.first;
    }
    else {
      ret.insert({count++, {rcount.second.toString(), rcount.first, 100.0 * rcount.first / static_cast<double>(total)}});
    }
  }

  if (total > 0) {
    ret.insert({count, {"Rest", rest, 100.0 * static_cast<double>(rest) / static_cast<double>(total)}});
  }
  else {
    ret.insert({count, {"Rest", rest, 100.0}});
  }

  return ret;
}

size_t Rings::loadFromFile(const std::string& filepath, const struct timespec& now)
{
  ifstream ifs(filepath);
  if (!ifs) {
    throw std::runtime_error("unable to open the file at " + filepath);
  }

  size_t inserted = 0;
  string line;
  dnsheader dnsHeader{};
  memset(&dnsHeader, 0, sizeof(dnsHeader));

  while (std::getline(ifs, line)) {
    boost::trim_right_if(line, boost::is_any_of(" \r\n\x1a"));
    boost::trim_left(line);
    bool isResponse = false;
    vector<string> parts;
    stringtok(parts, line, " \t,");

    if (parts.size() == 8) {
    }
    else if (parts.size() >= 11 && parts.size() <= 13) {
      isResponse = true;
    }
    else {
      cerr << "skipping line with " << parts.size() << "parts: " << line << endl;
      continue;
    }

    size_t idx = 0;
    vector<string> timeStr;
    stringtok(timeStr, parts.at(idx++), ".");
    if (timeStr.size() != 2) {
      cerr << "skipping invalid time " << parts.at(0) << endl;
      continue;
    }

    timespec when{};
    try {
      when.tv_sec = now.tv_sec + std::stoi(timeStr.at(0));
      when.tv_nsec = now.tv_nsec + static_cast<long>(std::stoi(timeStr.at(1)) * 100 * 1000 * 1000);
    }
    catch (const std::exception& e) {
      cerr << "error parsing time " << parts.at(idx - 1) << " from line " << line << endl;
      continue;
    }

    ComboAddress from(parts.at(idx++));
    ComboAddress dest;
    dnsdist::Protocol protocol(parts.at(idx++));
    if (isResponse) {
      dest = ComboAddress(parts.at(idx++));
    }
    /* skip ID */
    idx++;
    DNSName qname(parts.at(idx++));
    QType qtype(QType::chartocode(parts.at(idx++).c_str()));

    if (isResponse) {
      insertResponse(when, from, qname, qtype.getCode(), 0, 0, dnsHeader, dest, protocol);
    }
    else {
      insertQuery(when, from, qname, qtype.getCode(), 0, dnsHeader, protocol);
    }
    ++inserted;
  }

  return inserted;
}

bool Rings::Response::isACacheHit() const
{
  bool hit = ds.sin4.sin_family == 0;
  if (!hit && ds.isIPv4() && ds.sin4.sin_addr.s_addr == 0 && ds.sin4.sin_port == 0) {
    hit = true;
  }
  return hit;
}

bool Rings::shouldSkipDueToSampling()
{
  if (d_samplingRate == 0) {
    return false;
  }
  auto counter = d_samplingCounter++;
  return (counter % d_samplingRate) == 0;
}

uint32_t Rings::adjustForSamplingRate(uint32_t count) const
{
  const auto samplingRate = getSamplingRate();
  if (samplingRate > 0) {
    return count * samplingRate;
  }
  return count;
}
