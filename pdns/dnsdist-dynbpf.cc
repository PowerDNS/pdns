#include "dnsdist-dynbpf.hh"

#ifdef HAVE_EBPF

void DynBPFFilter::block(const ComboAddress& addr, const struct timespec& until)
{
  std::unique_lock<std::mutex> lock(d_mutex);

  const container_t::iterator it = d_entries.find(addr);
  if (it != d_entries.end()) {
    if (it->d_until < until) {
      d_entries.replace(it, BlockEntry(addr, until));
    }
  }
  else {
    d_bpf->block(addr);
    d_entries.insert(BlockEntry(addr, until));
  }
}

void DynBPFFilter::purgeExpired(const struct timespec& now)
{
  std::unique_lock<std::mutex> lock(d_mutex);

  typedef nth_index<container_t,1>::type ordered_until;
  ordered_until& ou = get<1>(d_entries);

  for (ordered_until::iterator it=ou.begin(); it != ou.end(); ) {
    if (it->d_until < now) {
      ComboAddress addr = it->d_addr;
      it = ou.erase(it);
      d_bpf->unblock(addr);
    }
    else {
      break;
    }
  }
}

std::vector<std::tuple<ComboAddress, uint64_t, struct timespec> > DynBPFFilter::getAddrStats()
{
  std::vector<std::tuple<ComboAddress, uint64_t, struct timespec> > result;
  if (!d_bpf) {
    return result;
  }

  const auto& stats = d_bpf->getAddrStats();
  for (const auto& stat : stats) {
    const container_t::iterator it = d_entries.find(stat.first);
    if (it != d_entries.end()) {
      result.push_back({stat.first, stat.second, it->d_until});
    }
  }
  return result;
}

#endif /* HAVE_EBPF */
