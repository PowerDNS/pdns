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
#include "dnsdist-async.hh"
#include "dnsdist-internal-queries.hh"
#include "dolog.hh"
#include "mplexer.hh"
#include "threadname.hh"

namespace dnsdist
{

AsynchronousHolder::Data::Data(bool failOpen) :
  d_failOpen(failOpen)
{
  auto [notifier, waiter] = pdns::channel::createNotificationQueue(true);
  // NOLINTNEXTLINE(cppcoreguidelines-prefer-member-initializer): how I am supposed to do that?
  d_waiter = std::move(waiter);
  // NOLINTNEXTLINE(cppcoreguidelines-prefer-member-initializer): how I am supposed to do that?
  d_notifier = std::move(notifier);
}

AsynchronousHolder::AsynchronousHolder(bool failOpen) :
  d_data(std::make_shared<Data>(failOpen))
{
  std::thread main([data = this->d_data] { mainThread(data); });
  main.detach();
}

AsynchronousHolder::~AsynchronousHolder()
{
  try {
    stop();
  }
  catch (...) {
  }
}

bool AsynchronousHolder::notify() const
{
  return d_data->d_notifier.notify();
}

bool AsynchronousHolder::wait(AsynchronousHolder::Data& data, FDMultiplexer& mplexer, std::vector<int>& readyFDs, int atMostMs)
{
  readyFDs.clear();
  mplexer.getAvailableFDs(readyFDs, atMostMs);
  if (readyFDs.empty()) {
    /* timeout */
    return true;
  }

  data.d_waiter.clear();
  return false;
}

void AsynchronousHolder::stop()
{
  {
    auto content = d_data->d_content.lock();
    d_data->d_done = true;
  }

  notify();
}

// NOLINTNEXTLINE(performance-unnecessary-value-param): this is a long-lived thread, and we want to make sure the reference count of the shared pointer has been increased
void AsynchronousHolder::mainThread(std::shared_ptr<Data> data)
{
  setThreadName("dnsdist/async");
  struct timeval now{};
  std::list<std::pair<uint16_t, std::unique_ptr<CrossProtocolQuery>>> expiredEvents;

  auto mplexer = std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent(1));
  mplexer->addReadFD(data->d_waiter.getDescriptor(), [](int, FDMultiplexer::funcparam_t&) {});
  std::vector<int> readyFDs;

  while (true) {
    bool shouldWait = true;
    int timeout = -1;
    dnsdist::configuration::refreshLocalRuntimeConfiguration();

    {
      auto content = data->d_content.lock();
      if (data->d_done) {
        return;
      }

      if (!content->empty()) {
        gettimeofday(&now, nullptr);
        struct timeval next = getNextTTD(*content);
        if (next <= now) {
          pickupExpired(*content, now, expiredEvents);
          shouldWait = false;
        }
        else {
          auto remainingUsec = uSec(next - now);
          timeout = static_cast<int>(std::round(static_cast<double>(remainingUsec) / 1000.0));
          if (timeout == 0 && remainingUsec > 0) {
            /* if we have less than 1 ms, let's wait at least 1 ms */
            timeout = 1;
          }
        }
      }
    }

    if (shouldWait) {
      auto timedOut = wait(*data, *mplexer, readyFDs, timeout);
      if (timedOut) {
        auto content = data->d_content.lock();
        gettimeofday(&now, nullptr);
        pickupExpired(*content, now, expiredEvents);
      }
    }

    while (!expiredEvents.empty()) {
      auto [queryID, query] = std::move(expiredEvents.front());
      expiredEvents.pop_front();
      if (!data->d_failOpen) {
        VERBOSESLOG(infolog("Asynchronous query %d has expired at %d.%d, notifying the sender", queryID, now.tv_sec, now.tv_usec),
                    dnsdist::logging::getTopLogger("async-thread")->info(Logr::Info, "Asynchronous query has expired, notifying the sender", "dns.question.id", Logging::Loggable(queryID)));
        auto sender = query->getTCPQuerySender();
        if (sender) {
          TCPResponse tresponse(std::move(query->query));
          sender->notifyIOError(now, std::move(tresponse));
        }
      }
      else {
        VERBOSESLOG(infolog("Asynchronous query %d has expired at %d.%d, resuming", queryID, now.tv_sec, now.tv_usec),
                    dnsdist::logging::getTopLogger("async-thread")->info(Logr::Info, "Asynchronous query has expired, resuming", "dns.question.id", Logging::Loggable(queryID)));
        resumeQuery(std::move(query));
      }
    }
  }
}

void AsynchronousHolder::push(uint16_t asyncID, uint16_t queryID, const struct timeval& ttd, std::unique_ptr<CrossProtocolQuery>&& query)
{
  bool needNotify = false;
  {
    auto content = d_data->d_content.lock();
    if (!content->empty()) {
      /* the thread is already waiting on a TTD expiry in addition to notifications,
         let's not wake it unless our TTD comes before the current one */
      const struct timeval next = getNextTTD(*content);
      if (ttd < next) {
        needNotify = true;
      }
    }
    else {
      /* the thread is currently only waiting for a notify */
      needNotify = true;
    }
    content->insert({std::move(query), ttd, asyncID, queryID});
  }

  if (needNotify) {
    notify();
  }
}

std::unique_ptr<CrossProtocolQuery> AsynchronousHolder::get(uint16_t asyncID, uint16_t queryID)
{
  /* no need to notify, worst case the thread wakes up for nothing because this was the next TTD */
  auto content = d_data->d_content.lock();
  auto contentIt = content->find(std::tie(queryID, asyncID));
  if (contentIt == content->end()) {
    timeval now{};
    gettimeofday(&now, nullptr);
    VERBOSESLOG(infolog("Asynchronous object %d not found at %d.%d", queryID, now.tv_sec, now.tv_usec),
                dnsdist::logging::getTopLogger("async-holder")->info(Logr::Info, "Asynchronous object not found", "dnsdist.async.id", Logging::Loggable(asyncID), "dns.question.id", Logging::Loggable(queryID)));
    return nullptr;
  }

  auto result = std::move(contentIt->d_query);
  content->erase(contentIt);
  return result;
}

void AsynchronousHolder::pickupExpired(content_t& content, const struct timeval& now, std::list<std::pair<uint16_t, std::unique_ptr<CrossProtocolQuery>>>& events)
{
  auto& idx = content.get<TTDTag>();
  for (auto contentIt = idx.begin(); contentIt != idx.end() && contentIt->d_ttd < now;) {
    events.emplace_back(contentIt->d_queryID, std::move(contentIt->d_query));
    contentIt = idx.erase(contentIt);
  }
}

struct timeval AsynchronousHolder::getNextTTD(const content_t& content)
{
  if (content.empty()) {
    throw std::runtime_error("AsynchronousHolder::getNextTTD() called on an empty holder");
  }

  return content.get<TTDTag>().begin()->d_ttd;
}

bool AsynchronousHolder::empty()
{
  return d_data->d_content.read_only_lock()->empty();
}

static bool resumeResponse(std::unique_ptr<CrossProtocolQuery>&& response)
{
  try {
    auto& ids = response->query.d_idstate;
    DNSResponse dnsResponse = response->getDR();

    auto result = processResponseAfterRules(response->query.d_buffer, dnsResponse, ids.cs->muted);
    if (!result) {
      /* easy */
      return true;
    }

    auto sender = response->getTCPQuerySender();
    if (sender) {
      struct timeval now{};
      gettimeofday(&now, nullptr);

      TCPResponse resp(std::move(response->query.d_buffer), std::move(response->query.d_idstate), nullptr, response->downstream);
      resp.d_async = true;
      sender->handleResponse(now, std::move(resp));
    }
  }
  catch (const std::exception& e) {
    VERBOSESLOG(infolog("Got exception while resuming cross-protocol response: %s", e.what()),
                dnsdist::logging::getTopLogger("async-holder")->error(Logr::Info, e.what(), "Got exception while resuming cross-protocol response"));
    return false;
  }

  return true;
}

static LockGuarded<std::deque<std::unique_ptr<CrossProtocolQuery>>> s_asynchronousEventsQueue;

bool queueQueryResumptionEvent(std::unique_ptr<CrossProtocolQuery>&& query)
{
  s_asynchronousEventsQueue.lock()->push_back(std::move(query));
  return true;
}

void handleQueuedAsynchronousEvents()
{
  while (true) {
    std::unique_ptr<CrossProtocolQuery> query;
    {
      // we do not want to hold the lock while resuming
      auto queue = s_asynchronousEventsQueue.lock();
      if (queue->empty()) {
        return;
      }

      query = std::move(queue->front());
      queue->pop_front();
    }
    if (query && !resumeQuery(std::move(query))) {
      VERBOSESLOG(infolog("Unable to resume asynchronous query event"),
                  dnsdist::logging::getTopLogger("async-holder")->info(Logr::Info, "Unable to resume asynchronous query event"));
    }
  }
}

bool resumeQuery(std::unique_ptr<CrossProtocolQuery>&& query)
{
  if (query->d_isResponse) {
    return resumeResponse(std::move(query));
  }

  DNSQuestion dnsQuestion = query->getDQ();

  auto result = processQueryAfterRules(dnsQuestion, query->downstream);
  if (result == ProcessQueryResult::Drop) {
    /* easy */
    return true;
  }
  if (result == ProcessQueryResult::PassToBackend) {
    if (query->downstream == nullptr) {
      return false;
    }

#ifdef HAVE_DNS_OVER_HTTPS
    if (dnsQuestion.ids.du != nullptr) {
      dnsQuestion.ids.du->downstream = query->downstream;
    }
#endif

    if (query->downstream->isTCPOnly() || !(dnsQuestion.getProtocol().isUDP() || dnsQuestion.getProtocol() == dnsdist::Protocol::DoH)) {
      query->downstream->passCrossProtocolQuery(std::move(query));
      return true;
    }

    auto queryID = dnsQuestion.getHeader()->id;
    /* at this point 'du', if it is not nullptr, is owned by the DoHCrossProtocolQuery
       which will stop existing when we return, so we need to increment the reference count
    */
    return assignOutgoingUDPQueryToBackend(query->downstream, queryID, dnsQuestion, query->query.d_buffer);
  }
  if (result == ProcessQueryResult::SendAnswer) {
    auto sender = query->getTCPQuerySender();
    if (!sender) {
      return false;
    }

    struct timeval now{};
    gettimeofday(&now, nullptr);

    TCPResponse response(std::move(query->query.d_buffer), std::move(query->query.d_idstate), nullptr, query->downstream);
    response.d_async = true;
    response.d_idstate.selfGenerated = true;

    try {
      sender->handleResponse(now, std::move(response));
      return true;
    }
    catch (const std::exception& e) {
      VERBOSESLOG(infolog("Got exception while resuming cross-protocol self-answered query: %s", e.what()),
                  dnsdist::logging::getTopLogger("async-holder")->error(Logr::Info, e.what(), "Got exception while resuming cross-protocol self-answered query"));
      return false;
    }
  }
  if (result == ProcessQueryResult::Asynchronous) {
    /* nope */
    SLOG(errlog("processQueryAfterRules returned 'asynchronous' while trying to resume an already asynchronous query"),
         dnsdist::logging::getTopLogger("async-holder")->info(Logr::Info, "processQueryAfterRules returned 'asynchronous' while trying to resume an already asynchronous query"));
    return false;
  }

  return false;
}

bool suspendQuery(DNSQuestion& dnsQuestion, uint16_t asyncID, uint16_t queryID, uint32_t timeoutMs)
{
  if (!g_asyncHolder) {
    return false;
  }

  struct timeval now{};
  gettimeofday(&now, nullptr);
  struct timeval ttd = now;
  ttd.tv_sec += timeoutMs / 1000;
  ttd.tv_usec += static_cast<decltype(ttd.tv_usec)>((timeoutMs % 1000) * 1000);
  normalizeTV(ttd);

  VERBOSESLOG(infolog("Suspending asynchronous query %d at %d.%d until %d.%d", queryID, now.tv_sec, now.tv_usec, ttd.tv_sec, ttd.tv_usec),
              dnsQuestion.getLogger()->info(Logr::Info, "Suspending asynchronous query", "dnsdist.async.until_sec", Logging::Loggable(ttd.tv_sec), "dnsdist.async.until_usec", Logging::Loggable(ttd.tv_usec)));
  auto query = getInternalQueryFromDQ(dnsQuestion, false);

  g_asyncHolder->push(asyncID, queryID, ttd, std::move(query));
  return true;
}

bool suspendResponse(DNSResponse& dnsResponse, uint16_t asyncID, uint16_t queryID, uint32_t timeoutMs)
{
  if (!g_asyncHolder) {
    return false;
  }

  struct timeval now{};
  gettimeofday(&now, nullptr);
  struct timeval ttd = now;
  ttd.tv_sec += timeoutMs / 1000;
  ttd.tv_usec += static_cast<decltype(ttd.tv_usec)>((timeoutMs % 1000) * 1000);
  normalizeTV(ttd);

  VERBOSESLOG(infolog("Suspending asynchronous response %d at %d.%d until %d.%d", queryID, now.tv_sec, now.tv_usec, ttd.tv_sec, ttd.tv_usec),
              dnsResponse.getLogger()->info(Logr::Info, "Suspending asynchronous response", "dnsdist.async.until_sec", Logging::Loggable(ttd.tv_sec), "dnsdist.async.until_usec", Logging::Loggable(ttd.tv_usec)));
  auto query = getInternalQueryFromDQ(dnsResponse, true);
  query->d_isResponse = true;
  query->downstream = dnsResponse.d_downstream;

  g_asyncHolder->push(asyncID, queryID, ttd, std::move(query));
  return true;
}

std::unique_ptr<AsynchronousHolder> g_asyncHolder;
}
