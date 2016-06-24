#pragma once
#include "config.h"

#include <mutex>

#include "bpf-filter.hh"
#include "iputils.hh"

#ifdef HAVE_EBPF

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>

class DynBPFFilter
{
public:
  DynBPFFilter(std::shared_ptr<BPFFilter> bpf): d_bpf(bpf)
  {
  }
  ~DynBPFFilter()
  {
  }
  void block(const ComboAddress& addr, const struct timespec& until);
  void purgeExpired(const struct timespec& now);
private:
  struct BlockEntry
  {
    BlockEntry(const ComboAddress& addr, const struct timespec until): d_addr(addr), d_until(until)
    {
    }
    ComboAddress d_addr;
    struct timespec d_until;
  };
  typedef multi_index_container<BlockEntry,
                                indexed_by <
                                  ordered_unique< member<BlockEntry,ComboAddress,&BlockEntry::d_addr>, ComboAddress::addressOnlyLessThan >,
                                  ordered_non_unique< member<BlockEntry,struct timespec,&BlockEntry::d_until> >
                                  >
                                > container_t;
  container_t d_entries;
  std::mutex d_mutex;
  std::shared_ptr<BPFFilter> d_bpf;
};

#endif /* HAVE_EBPF */
