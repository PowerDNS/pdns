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
#include <string>
#include <atomic>
#include <stdint.h>
#include <mutex>
#include <map>
#include <vector>

/* please do NOT add PowerDNS specific includes/things to this file, we're trying 
   to make it useful for other projects as well! */

/* Goal: you can compile this in safely, but it won't do anything unless PDNS_TRACE_MEMORY is defined. */

class MallocTracer
{
public:
  void* malloc(size_t size);
  void free(void*);
  uint64_t getAllocs(const std::string& = std::string()) const { return d_allocs; }
  uint64_t getAllocFlux(const std::string& = std::string()) const { return d_allocflux; }
  uint64_t getTotAllocated(const std::string& = std::string()) const { return d_totAllocated; }
  uint64_t getNumOut()
  {
    std::lock_guard<std::mutex> lock(d_mut);
    return d_sizes.size();
  }
  struct AllocStats
  {
    int count;
    std::map<unsigned int, unsigned int> sizes;
  };
  typedef std::vector<std::pair<MallocTracer::AllocStats,
    std::vector<void*>>>
    allocators_t;
  allocators_t topAllocators(int num = -1);
  std::string topAllocatorsString(int num = -1);
  void clearAllocators();

private:
  static std::vector<void*> makeBacktrace();
  std::atomic<uint64_t> d_allocs{0}, d_allocflux{0}, d_totAllocated{0};
  std::map<std::vector<void*>, AllocStats> d_stats;
  std::map<void*, size_t> d_sizes;
  std::mutex d_mut;
};

extern MallocTracer* g_mtracer;
