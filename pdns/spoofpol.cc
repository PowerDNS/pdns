#include "spoofpol.hh"

void SpoofPolicy::report(const ComboAddress& remote, const std::string& auth, int policy, const struct timeval& tv)
{
  SpoofEntry se;
  se.ttd = tv.tv_sec + 3600;
  se.policy = policy;
  d_spoofmap[make_pair(remote,auth)] = se;
}

int SpoofPolicy::getPolicy(const ComboAddress& remote, const std::string& auth, const struct timeval& tv)
{
  spoofmap_t::iterator iter = d_spoofmap.find(make_pair(remote,auth));
  if(iter == d_spoofmap.end())
    return 0;

  if(iter->second.ttd > tv.tv_sec) 
    return iter->second.policy;
  else 
    d_spoofmap.erase(iter);

  return 0;
}
