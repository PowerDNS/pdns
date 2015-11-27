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
  void* malloc (size_t size);
  void free(void*);
  uint64_t getAllocs(const std::string& = std::string()) const { return d_allocs; }
  uint64_t getAllocFlux(const std::string& = std::string()) const { return d_allocflux; }
  uint64_t getTotAllocated(const std::string& = std::string()) const { return d_totAllocated; }
  uint64_t getNumOut() { std::lock_guard<std::mutex> lock(d_mut); return d_sizes.size(); }
  struct AllocStats
  {
    int count;
    std::map<unsigned int, unsigned int> sizes;
  };
  typedef std::vector<std::pair<MallocTracer::AllocStats, 
				std::vector<void*> > > allocators_t;
  allocators_t topAllocators(int num=-1);
  std::string topAllocatorsString(int num=-1);
  void clearAllocators();

private:
  static std::vector<void*> makeBacktrace();
  std::atomic<uint64_t> d_allocs{0}, d_allocflux{0}, d_totAllocated{0};
  std::map<std::vector<void*>, AllocStats> d_stats;
  std::map<void*, size_t> d_sizes;
  std::mutex d_mut;
};

extern MallocTracer* g_mtracer;
