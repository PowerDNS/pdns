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

#include <sys/time.h>
#include <thread>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/tag.hpp>

#include "dnsname.hh"
#include "qtype.hh"

namespace pdns
{
using namespace ::boost::multi_index;

// ATM we have one task type, if we get more, the unique key in the index needs to be adapted
struct ResolveTask
{
  DNSName d_qname;
  uint16_t d_qtype;
  time_t d_deadline;
  bool d_refreshMode; // Whether to run this task in regular mode (false) or in the mode that refreshes almost expired tasks
  // Use a function pointer as comparing std::functions is a nuisance
  void (*d_func)(const struct timeval& now, bool logErrors, const ResolveTask& task);

  bool operator<(const ResolveTask& a) const
  {
    return std::tie(d_qname, d_qtype, d_refreshMode, d_func) < std::tie(a.d_qname, a.d_qtype, a.d_refreshMode, a.d_func);
  }
  bool run(bool logErrors);
};

class TaskQueue
{
public:
  bool empty() const
  {
    return d_queue.empty();
  }

  size_t size() const
  {
    return d_queue.size();
  }

  void push(ResolveTask&& task);
  ResolveTask pop();

  uint64_t getPushes()
  {
    return d_pushes;
  }

  uint64_t getExpired()
  {
    return d_expired;
  }

  void incExpired()
  {
    d_expired++;
  }

  void clear()
  {
    d_queue.clear();
  }

private:
  struct HashTag
  {
  };

  struct SequencedTag
  {
  };

  typedef multi_index_container<
    ResolveTask,
    indexed_by<
      hashed_unique<tag<HashTag>,
                    composite_key<ResolveTask,
                                  member<ResolveTask, DNSName, &ResolveTask::d_qname>,
                                  member<ResolveTask, uint16_t, &ResolveTask::d_qtype>,
                                  member<ResolveTask, bool, &ResolveTask::d_refreshMode>>>,
      sequenced<tag<SequencedTag>>>>
    queue_t;

  queue_t d_queue;
  uint64_t d_pushes{0};
  uint64_t d_expired{0};
};

}
