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
#include "logger.hh"
#include "stat_t.hh"
#include "syncres.hh"

static LockGuarded<pdns::TaskQueue> s_taskQueue;
static pdns::stat_t s_almost_expired_tasks_pushed;
static pdns::stat_t s_almost_expired_tasks_run;
static pdns::stat_t s_almost_expired_tasks_exceptions;

static void resolve(const struct timeval& now, bool logErrors, const pdns::ResolveTask& task)
{
  const string msg = "Exception while running a background ResolveTask";
  SyncRes sr(now);
  vector<DNSRecord> ret;
  sr.setRefreshAlmostExpired(task.d_refreshMode);
  try {
    g_log << Logger::Debug << "TaskQueue: resolving " << task.d_qname.toString() << '|' << QType(task.d_qtype).toString() << endl;
    int res = sr.beginResolve(task.d_qname, QType(task.d_qtype), QClass::IN, ret);
    ++s_almost_expired_tasks_run;
    g_log << Logger::Debug << "TaskQueue: DONE resolving " << task.d_qname.toString() << '|' << QType(task.d_qtype).toString() << ": " << res << endl;
  }
  catch (const std::exception& e) {
    ++s_almost_expired_tasks_exceptions;
    g_log << Logger::Error << msg << ": " << e.what() << endl;
  }
  catch (const PDNSException& e) {
    ++s_almost_expired_tasks_exceptions;
    g_log << Logger::Notice << msg << ": " << e.reason << endl;
  }
  catch (const ImmediateServFailException& e) {
    ++s_almost_expired_tasks_exceptions;
    if (logErrors) {
      g_log << Logger::Notice << msg << ": " << e.reason << endl;
    }
  }
  catch (const PolicyHitException& e) {
    ++s_almost_expired_tasks_exceptions;
    if (logErrors) {
      g_log << Logger::Notice << msg << ": PolicyHit" << endl;
    }
  }
  catch (...) {
    ++s_almost_expired_tasks_exceptions;
    g_log << Logger::Error << msg << endl;
  }
}

void runTaskOnce(bool logErrors)
{
  pdns::ResolveTask task;
  {
    auto lock = s_taskQueue.lock();
    if (lock->empty()) {
      return;
    }
    task = lock->pop();
  }
  bool expired = task.run(logErrors);
  if (expired) {
    s_taskQueue.lock()->incExpired();
  }
}

void pushAlmostExpiredTask(const DNSName& qname, uint16_t qtype, time_t deadline)
{
  ++s_almost_expired_tasks_pushed;
  pdns::ResolveTask task{qname, qtype, deadline, true, resolve};
  s_taskQueue.lock()->push(std::move(task));
}

uint64_t getTaskPushes()
{
  return s_taskQueue.lock()->getPushes();
}

uint64_t getTaskExpired()
{
  return s_taskQueue.lock()->getExpired();
}

uint64_t getTaskSize()
{
  return s_taskQueue.lock()->size();
}

uint64_t getAlmostExpiredTasksPushed()
{
  return s_almost_expired_tasks_pushed;
}

uint64_t getAlmostExpiredTasksRun()
{
  return s_almost_expired_tasks_run;
}

uint64_t getAlmostExpiredTaskExceptions()
{
  return s_almost_expired_tasks_exceptions;
}
