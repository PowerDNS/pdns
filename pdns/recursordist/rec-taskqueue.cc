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

#include "rec-taskqueue.hh"
#include "taskqueue.hh"
#include "lock.hh"
#include "logging.hh"
#include "stat_t.hh"
#include "syncres.hh"

// For rate limiting purposes we maintain a set of tasks recently submitted.
class TimedSet
{
public:
  TimedSet(time_t time) :
    d_expiry_seconds(time)
  {
  }

  uint64_t purge(time_t now)
  {
    // This purge is relatively cheap, as we're walking an ordered index
    uint64_t erased = 0;
    auto& ind = d_set.template get<time_t>();
    auto iter = ind.begin();
    while (iter != ind.end()) {
      if (iter->d_ttd < now) {
        ++erased;
        iter = ind.erase(iter);
      }
      else {
        break;
      }
    }
    return erased;
  }

  bool insert(time_t now, const pdns::ResolveTask& task)
  {
    // We periodically purge
    if (++d_count % 1024 == 0) {
      purge(now);
    }
    time_t ttd = now + d_expiry_seconds;
    bool inserted = d_set.emplace(task, ttd).second;
    if (!inserted) {
      uint64_t erased = purge(now);
      // Try again if the purge deleted at least one entry
      if (erased > 0) {
        inserted = d_set.emplace(task, ttd).second;
      }
    }
    return inserted;
  }

  void clear()
  {
    d_set.clear();
  }

private:
  struct Entry
  {
    Entry(pdns::ResolveTask task, time_t ttd) :
      d_task(std::move(task)), d_ttd(ttd) {}
    pdns::ResolveTask d_task;
    time_t d_ttd;
  };

  using timed_set_t = multi_index_container<
    Entry,
    indexed_by<ordered_unique<tag<pdns::ResolveTask>,
                              member<Entry, pdns::ResolveTask, &Entry::d_task>>,
               ordered_non_unique<tag<time_t>,
                                  member<Entry, time_t, &Entry::d_ttd>>>>;
  timed_set_t d_set;
  time_t d_expiry_seconds;
  unsigned int d_count{0};
};

struct Queue
{
  pdns::TaskQueue queue;
  TimedSet rateLimitSet{60};
};
static LockGuarded<Queue> s_taskQueue;

struct taskstats
{
  pdns::stat_t pushed;
  pdns::stat_t run;
  pdns::stat_t exceptions;
};

static struct taskstats s_almost_expired_tasks;
static struct taskstats s_resolve_tasks;

// forceNoQM is true means resolve using no qm, false means use default value
static void resolveInternal(const struct timeval& now, bool logErrors, const pdns::ResolveTask& task, bool forceNoQM) noexcept
{
  auto log = g_slog->withName("taskq")->withValues("name", Logging::Loggable(task.d_qname), "qtype", Logging::Loggable(QType(task.d_qtype).toString()), "netmask", Logging::Loggable(task.d_netmask.empty() ? "" : task.d_netmask.toString()));
  const string msg = "Exception while running a background ResolveTask";
  SyncRes resolver(now);
  vector<DNSRecord> ret;
  resolver.setRefreshAlmostExpired(task.d_refreshMode);
  resolver.setQuerySource(task.d_netmask);
  if (forceNoQM) {
    resolver.setQNameMinimization(false);
  }
  bool exceptionOccurred = true;
  try {
    log->info(Logr::Debug, "resolving", "refresh", Logging::Loggable(task.d_refreshMode));
    int res = resolver.beginResolve(task.d_qname, QType(task.d_qtype), QClass::IN, ret);
    exceptionOccurred = false;
    log->info(Logr::Debug, "done", "rcode", Logging::Loggable(res), "records", Logging::Loggable(ret.size()));
  }
  catch (const std::exception& e) {
    log->error(Logr::Warning, msg, e.what());
  }
  catch (const PDNSException& e) {
    log->error(Logr::Warning, msg, e.reason);
  }
  catch (const ImmediateServFailException& e) {
    if (logErrors) {
      log->error(Logr::Warning, msg, e.reason);
    }
  }
  catch (const PolicyHitException& e) {
    if (logErrors) {
      log->error(Logr::Warning, msg, "PolicyHit");
    }
  }
  catch (...) {
    log->error(Logr::Warning, msg, "Unexpected exception");
  }
  if (exceptionOccurred) {
    if (task.d_refreshMode) {
      ++s_almost_expired_tasks.exceptions;
    }
    else {
      ++s_resolve_tasks.exceptions;
    }
  }
  else {
    if (task.d_refreshMode) {
      ++s_almost_expired_tasks.run;
    }
    else {
      ++s_resolve_tasks.run;
    }
  }
}

static void resolveForceNoQM(const struct timeval& now, bool logErrors, const pdns::ResolveTask& task) noexcept
{
  resolveInternal(now, logErrors, task, true);
}

static void resolve(const struct timeval& now, bool logErrors, const pdns::ResolveTask& task) noexcept
{
  resolveInternal(now, logErrors, task, false);
}

static void tryDoT(const struct timeval& now, bool logErrors, const pdns::ResolveTask& task) noexcept
{
  auto log = g_slog->withName("taskq")->withValues("method", Logging::Loggable("tryDoT"), "name", Logging::Loggable(task.d_qname), "qtype", Logging::Loggable(QType(task.d_qtype).toString()), "ip", Logging::Loggable(task.d_ip));
  const string msg = "Exception while running a background tryDoT task";
  SyncRes resolver(now);
  vector<DNSRecord> ret;
  resolver.setRefreshAlmostExpired(false);
  bool exceptionOccurred = true;
  try {
    log->info(Logr::Debug, "trying DoT");
    bool tryOK = resolver.tryDoT(task.d_qname, QType(task.d_qtype), task.d_nsname, task.d_ip, now.tv_sec);
    exceptionOccurred = false;
    log->info(Logr::Debug, "done", "ok", Logging::Loggable(tryOK));
  }
  catch (const std::exception& e) {
    log->error(Logr::Warning, msg, e.what());
  }
  catch (const PDNSException& e) {
    log->error(Logr::Warning, msg, e.reason);
  }
  catch (const ImmediateServFailException& e) {
    if (logErrors) {
      log->error(Logr::Warning, msg, e.reason);
    }
  }
  catch (const PolicyHitException& e) {
    if (logErrors) {
      log->error(Logr::Notice, msg, "PolicyHit");
    }
  }
  catch (...) {
    log->error(Logr::Warning, msg, "Unexpected exception");
  }
  if (exceptionOccurred) {
    ++s_resolve_tasks.exceptions;
  }
  else {
    ++s_resolve_tasks.run;
  }
}

void runTasks(size_t max, bool logErrors)
{
  for (size_t count = 0; count < max; count++) {
    if (!runTaskOnce(logErrors)) {
      // No more tasks in queue
      break;
    }
  }
}

bool runTaskOnce(bool logErrors)
{
  pdns::ResolveTask task;
  {
    auto lock = s_taskQueue.lock();
    if (lock->queue.empty()) {
      return false;
    }
    task = lock->queue.pop();
  }
  bool expired = task.run(logErrors);
  if (expired) {
    s_taskQueue.lock()->queue.incExpired();
  }
  return true;
}

void pushAlmostExpiredTask(const DNSName& qname, uint16_t qtype, time_t deadline, const Netmask& netmask)
{
  if (SyncRes::isUnsupported(qtype)) {
    auto log = g_slog->withName("taskq")->withValues("name", Logging::Loggable(qname), "qtype", Logging::Loggable(QType(qtype).toString()), "netmask", Logging::Loggable(netmask.empty() ? "" : netmask.toString()));
    log->error(Logr::Error, "Cannot push task", "qtype unsupported");
    return;
  }
  pdns::ResolveTask task{qname, qtype, deadline, true, resolve, {}, {}, netmask};
  if (s_taskQueue.lock()->queue.push(std::move(task))) {
    ++s_almost_expired_tasks.pushed;
  }
}

void pushResolveTask(const DNSName& qname, uint16_t qtype, time_t now, time_t deadline, bool forceQMOff)
{
  if (SyncRes::isUnsupported(qtype)) {
    auto log = g_slog->withName("taskq")->withValues("name", Logging::Loggable(qname), "qtype", Logging::Loggable(QType(qtype).toString()));
    log->error(Logr::Error, "Cannot push task", "qtype unsupported");
    return;
  }
  auto func = forceQMOff ? resolveForceNoQM : resolve;
  pdns::ResolveTask task{qname, qtype, deadline, false, func, {}, {}, {}};
  auto lock = s_taskQueue.lock();
  bool inserted = lock->rateLimitSet.insert(now, task);
  if (inserted) {
    if (lock->queue.push(std::move(task))) {
      ++s_resolve_tasks.pushed;
    }
  }
}

bool pushTryDoTTask(const DNSName& qname, uint16_t qtype, const ComboAddress& ipAddress, time_t deadline, const DNSName& nsname)
{
  if (SyncRes::isUnsupported(qtype)) {
    auto log = g_slog->withName("taskq")->withValues("name", Logging::Loggable(qname), "qtype", Logging::Loggable(QType(qtype).toString()));
    log->error(Logr::Error, "Cannot push task", "qtype unsupported");
    return false;
  }

  pdns::ResolveTask task{qname, qtype, deadline, false, tryDoT, ipAddress, nsname, {}};
  bool pushed = s_taskQueue.lock()->queue.push(std::move(task));
  if (pushed) {
    ++s_almost_expired_tasks.pushed;
  }
  return pushed;
}

uint64_t getTaskPushes()
{
  return s_taskQueue.lock()->queue.getPushes();
}

uint64_t getTaskExpired()
{
  return s_taskQueue.lock()->queue.getExpired();
}

uint64_t getTaskSize()
{
  return s_taskQueue.lock()->queue.size();
}

void taskQueueClear()
{
  auto lock = s_taskQueue.lock();
  lock->queue.clear();
  lock->rateLimitSet.clear();
}

pdns::ResolveTask taskQueuePop()
{
  return s_taskQueue.lock()->queue.pop();
}

uint64_t getAlmostExpiredTasksPushed()
{
  return s_almost_expired_tasks.pushed;
}

uint64_t getAlmostExpiredTasksRun()
{
  return s_almost_expired_tasks.run;
}

uint64_t getAlmostExpiredTaskExceptions()
{
  return s_almost_expired_tasks.exceptions;
}

uint64_t getResolveTasksPushed()
{
  return s_almost_expired_tasks.pushed;
}

uint64_t getResolveTasksRun()
{
  return s_almost_expired_tasks.run;
}

uint64_t getResolveTaskExceptions()
{
  return s_almost_expired_tasks.exceptions;
}

bool taskQTypeIsSupported(QType qtype)
{
  return !SyncRes::isUnsupported(qtype);
}
