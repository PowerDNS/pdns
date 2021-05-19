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

#include "taskqueue.hh"

#include "logger.hh"
#include "syncres.hh"

namespace pdns
{

bool TaskQueue::empty() const
{
  return d_queue.empty();
}

size_t TaskQueue::size() const
{
  return d_queue.size();
}

void TaskQueue::push(const ResolveTask&& task)
{
  // Insertion fails if it's already there, no problem since we're already scheduled
  // and the deadline would remain the same anyway.
  auto result = d_queue.insert(std::move(task));
  if (result.second) {
    d_pushes++;
  }
}

ResolveTask TaskQueue::pop()
{
  ResolveTask ret = d_queue.get<SequencedTag>().front();
  d_queue.get<SequencedTag>().pop_front();
  return ret;
}

bool TaskQueue::runOnce(bool logErrors)
{
  if (d_queue.empty()) {
    return false;
  }
  ResolveTask task = pop();
  struct timeval now;
  gettimeofday(&now, 0);
  if (task.d_deadline >= now.tv_sec) {
    SyncRes sr(now);
    vector<DNSRecord> ret;
    sr.setRefreshAlmostExpired(task.d_refreshMode);
    try {
      g_log << Logger::Debug << "TaskQueue: resolving " << task.d_qname.toString() << '|' << QType(task.d_qtype).getName() << endl;
      int res = sr.beginResolve(task.d_qname, QType(task.d_qtype), QClass::IN, ret);
      g_log << Logger::Debug << "TaskQueue: DONE resolving " << task.d_qname.toString() << '|' << QType(task.d_qtype).getName() << ": " << res << endl;
    }
    catch (const std::exception& e) {
      g_log << Logger::Error << "Exception while running the background task queue: " << e.what() << endl;
    }
    catch (const PDNSException& e) {
      g_log << Logger::Notice << "Exception while running the background task queue: " << e.reason << endl;
    }
    catch (const ImmediateServFailException& e) {
      if (logErrors) {
        g_log << Logger::Notice << "Exception while running the background task queue: " << e.reason << endl;
      }
    }
    catch (const PolicyHitException& e) {
      if (logErrors) {
        g_log << Logger::Notice << "Policy hit while running the background task queue" << endl;
      }
    }
    catch (...) {
      g_log << Logger::Error << "Exception while running the background task queue" << endl;
    }
  }
  else {
    // Deadline passed
    g_log << Logger::Debug << "TaskQueue: deadline for " << task.d_qname.toString() << '|' << QType(task.d_qtype).getName() << " passed" << endl;
    d_expired++;
  }
  return true;
}

void TaskQueue::runAll(bool logErrors)
{
  while (runOnce(logErrors)) {
    /* empty */
  }
}

uint64_t* TaskQueue::getPushes() const
{
  return new uint64_t(d_pushes);
}

uint64_t* TaskQueue::getExpired() const
{
  return new uint64_t(d_expired);
}

uint64_t* TaskQueue::getSize() const
{
  return new uint64_t(size());
}

} /* namespace pdns */
