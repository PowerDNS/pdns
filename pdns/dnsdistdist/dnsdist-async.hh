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

#include <thread>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/key_extractors.hpp>

#include "channel.hh"
#include "dnsdist-tcp.hh"

namespace dnsdist
{
class AsynchronousHolder
{
public:
  AsynchronousHolder(bool failOpen = true);
  ~AsynchronousHolder();
  void push(uint16_t asyncID, uint16_t queryID, const struct timeval& ttd, std::unique_ptr<CrossProtocolQuery>&& query);
  std::unique_ptr<CrossProtocolQuery> get(uint16_t asyncID, uint16_t queryID);
  bool empty();
  void stop();

private:
  struct TTDTag
  {
  };
  struct IDTag
  {
  };

  struct Entry
  {
    /* not used by any of the indexes, so mutable */
    mutable std::unique_ptr<CrossProtocolQuery> d_query;
    struct timeval d_ttd;
    uint16_t d_asyncID;
    uint16_t d_queryID;
  };

  using content_t = multi_index_container<
    Entry,
    indexed_by<
      ordered_unique<tag<IDTag>,
                     composite_key<
                       Entry,
                       member<Entry, uint16_t, &Entry::d_queryID>,
                       member<Entry, uint16_t, &Entry::d_asyncID>>>,
      ordered_non_unique<tag<TTDTag>,
                         member<Entry, struct timeval, &Entry::d_ttd>>>>;

  static void pickupExpired(content_t&, const struct timeval& now, std::list<std::pair<uint16_t, std::unique_ptr<CrossProtocolQuery>>>& expiredEvents);
  static struct timeval getNextTTD(const content_t&);

  struct Data
  {
    Data(bool failOpen);
    Data(const Data&) = delete;
    Data(Data&&) = delete;
    Data& operator=(const Data&) = delete;
    Data& operator=(Data&&) = delete;
    ~Data() = default;

    LockGuarded<content_t> d_content;
    pdns::channel::Notifier d_notifier;
    pdns::channel::Waiter d_waiter;
    bool d_failOpen{true};
    bool d_done{false};
  };
  std::shared_ptr<Data> d_data{nullptr};

  static void mainThread(std::shared_ptr<Data> data);
  static bool wait(Data& data, FDMultiplexer& mplexer, std::vector<int>& readyFDs, int atMostMs);
  bool notify() const;
};

bool suspendQuery(DNSQuestion& dnsQuestion, uint16_t asyncID, uint16_t queryID, uint32_t timeoutMs);
bool suspendResponse(DNSResponse& dnsResponse, uint16_t asyncID, uint16_t queryID, uint32_t timeoutMs);
bool queueQueryResumptionEvent(std::unique_ptr<CrossProtocolQuery>&& query);
bool resumeQuery(std::unique_ptr<CrossProtocolQuery>&& query);
void handleQueuedAsynchronousEvents();

extern std::unique_ptr<AsynchronousHolder> g_asyncHolder;
}
