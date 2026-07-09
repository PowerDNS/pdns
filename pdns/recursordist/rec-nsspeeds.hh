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
#pragma once

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/multi_index/sequenced_index.hpp>

#include "iputils.hh"

using namespace ::boost::multi_index;

/** Class that implements a decaying EWMA.
    This class keeps an exponentially weighted moving average which, additionally, decays over time.
    The decaying is only done on get.
*/

//! This represents a number of decaying Ewmas, used to store performance per nameserver-name.
/** Modelled to work mostly like the underlying DecayingEwma */
class DecayingEwmaCollection
{
private:
  struct DecayingEwma
  {
  public:
    void submit(int arg, const struct timeval& now)
    {
      auto val = static_cast<float>(arg);
      auto usecTS = uSec(now);
      if (d_decayed_value == 0) {
        d_decayed_value = val;
      }
      else {
        auto int_diff = static_cast<int64_t>(d_last_timestamp - usecTS); // usecs
        auto diff = static_cast<float>(int_diff) / 1000000.0F; // seconds
        auto factor = expf(diff / DecayingEwmaCollection::s_memory) / 2.0F; // might be '0.5', or 0.0001
        auto original_value = static_cast<float>(d_last_value);
        d_decayed_value = (1.0F - factor) * val + factor * original_value;
      }
      d_last_value = arg;
      d_last_timestamp = usecTS;
    }

    float get(float factor)
    {
      return d_decayed_value *= factor;
    }

    [[nodiscard]] float peek() const
    {
      return d_decayed_value;
    }

    [[nodiscard]] int last() const
    {
      return d_last_value;
    }

    uint64_t d_last_timestamp{0};
    float d_decayed_value{0};
    int d_last_value{0};
  };

public:
  static constexpr float s_memory = 60; // higher value means we remember past performance longer

  DecayingEwmaCollection(DNSName name, const struct timeval val = {0, 0}) :
    d_name(std::move(name)), d_lastget(val)
  {
  }

  void submit(const ComboAddress& remote, int usecs, const struct timeval& now) const
  {
    d_collection[remote].submit(usecs, now);
  }

  float getFactor(const struct timeval& now) const
  {
    float diff = makeFloat(d_lastget - now);
    return expf(diff / s_memory); // is 1.0 or less
  }

  bool stale(time_t limit) const
  {
    return limit > d_lastget.tv_sec;
  }

  void purge(const std::map<ComboAddress, float>& keep) const
  {
    for (auto iter = d_collection.begin(); iter != d_collection.end();) {
      if (keep.find(iter->first) != keep.end()) {
        ++iter;
      }
      else {
        iter = d_collection.erase(iter);
      }
    }
  }

  void insert(const ComboAddress& address, float val, int last, uint64_t last_ts)
  {
    d_collection.insert(std::make_pair(address, DecayingEwma{.d_last_timestamp = last_ts, .d_decayed_value = val, .d_last_value = last}));
  }

  // d_collection is the modifyable part of the record, we index on DNSName and timeval, and DNSName never changes
  mutable std::map<ComboAddress, DecayingEwma> d_collection;
  DNSName d_name;
  struct timeval d_lastget;
};

class nsspeeds_t : public multi_index_container<DecayingEwmaCollection,
                                                indexed_by<
                                                  hashed_unique<tag<DNSName>, member<DecayingEwmaCollection, const DNSName, &DecayingEwmaCollection::d_name>>,
                                                  ordered_non_unique<tag<timeval>, member<DecayingEwmaCollection, timeval, &DecayingEwmaCollection::d_lastget>>>>
{
public:
  const auto& find_or_enter(const DNSName& name, const struct timeval& now)
  {
    const auto iter = insert(DecayingEwmaCollection{name, now}).first;
    return *iter;
  }

  const auto& find_or_enter(const DNSName& name)
  {
    const auto iter = insert(DecayingEwmaCollection{name}).first;
    return *iter;
  }

  float fastest(const DNSName& name, const struct timeval& now)
  {
    auto& ind = get<DNSName>();
    auto iter = insert(DecayingEwmaCollection{name, now}).first;
    if (iter->d_collection.empty()) {
      return 0;
    }
    // This could happen if find(DNSName) entered an entry; it's used only by test code
    if (iter->d_lastget.tv_sec == 0 && iter->d_lastget.tv_usec == 0) {
      ind.modify(iter, [&](DecayingEwmaCollection& dec) { dec.d_lastget = now; });
    }

    float ret = std::numeric_limits<float>::max();
    const float factor = iter->getFactor(now);
    for (auto& entry : iter->d_collection) {
      ret = std::min(ret, entry.second.get(factor));
    }
    ind.modify(iter, [&](DecayingEwmaCollection& dec) { dec.d_lastget = now; });
    return ret;
  }

  size_t getPB(const string& serverID, size_t maxSize, std::string& ret) const;
  size_t putPB(time_t cutoff, const std::string& pbuf);

private:
  template <typename T, typename U>
  static void getPBEntry(T& message, U& entry);
  template <typename T>
  bool putPBEntry(time_t cutoff, T& message);
};
