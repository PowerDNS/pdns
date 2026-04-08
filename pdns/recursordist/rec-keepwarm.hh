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

#include <ctime>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/tag.hpp>
#include <utility>

#include "dnsname.hh"
#include "qtype.hh"

namespace rec
{
using namespace ::boost::multi_index;

struct KeepWarmEntry
{
  KeepWarmEntry(DNSName name, QType qtype, time_t ttd = 0) : d_qname(std::move(name)), d_ttd(ttd), d_qtype(qtype) {}
  DNSName d_qname;
  time_t d_ttd;
  uint16_t d_qtype;
};

class KeepWarm
{
public:
  struct QNameQTypeTag
  {
  };

  struct TTDTag
  {
  };

  using Queue = multi_index_container<
    KeepWarmEntry,
    indexed_by<ordered_unique<tag<QNameQTypeTag>,
                              composite_key<KeepWarmEntry,
                                            member<KeepWarmEntry, DNSName, &KeepWarmEntry::d_qname>,
                                            member<KeepWarmEntry, uint16_t, &KeepWarmEntry::d_qtype>>>,
               ordered_non_unique<tag<TTDTag>, member<KeepWarmEntry, time_t, &KeepWarmEntry::d_ttd>, std::less<>>>>;

  [[nodiscard]] const Queue& get() const
  {
    return d_queue;
  }
  void modifyTTD(const DNSName& qname, uint16_t qtype, uint32_t ttd)
  {
      auto item = d_queue.find(std::tie(qname, qtype));
      if (item != d_queue.end()) {
        d_queue.modify(item, [ttd](rec::KeepWarmEntry& entry) { entry.d_ttd = ttd; });
      }
    
  }
  void emplace(const DNSName& name, uint16_t qtype)
  {
    d_queue.emplace(name, qtype);
  }
  Queue::iterator erase(Queue::iterator iter)
  {
    return d_queue.erase(iter);
  }
  Queue::iterator begin()
  {
    return d_queue.begin();
  }
  Queue::iterator end()
  {
    return d_queue.end();
  }

private:
  Queue d_queue;
};
}
