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

#include "logging.hh"
#include "syncres.hh"

namespace pdns
{

bool TaskQueue::push(ResolveTask&& task)
{
  // Insertion fails if it's already there, no problem since we're already scheduled
  auto result = d_queue.insert(std::move(task)).second;
  if (result) {
    d_pushes++;
  }
  return result;
}

ResolveTask TaskQueue::pop()
{
  ResolveTask ret = d_queue.get<SequencedTag>().front();
  d_queue.get<SequencedTag>().pop_front();
  return ret;
}

bool ResolveTask::run(bool logErrors) const
{
  if (d_func == nullptr) {
    auto log = g_slog->withName("taskq")->withValues("name", Logging::Loggable(d_qname), "qtype", Logging::Loggable(QType(d_qtype).toString()));
    log->error(Logr::Debug, "null task");
    return false;
  }
  struct timeval now{};
  Utility::gettimeofday(&now);
  if (d_deadline >= now.tv_sec) {
    d_func(now, logErrors, *this);
  }
  else {
    // Deadline passed
    auto log = g_slog->withName("taskq")->withValues("name", Logging::Loggable(d_qname), "qtype", Logging::Loggable(QType(d_qtype).toString()));
    log->info(Logr::Debug, "deadline passed");
    return true;
  }
  return false;
}

} /* namespace pdns */

namespace boost
{
size_t hash_value(const ComboAddress& address)
{
  return ComboAddress::addressOnlyHash()(address);
}
}
