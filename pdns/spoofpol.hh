#ifndef PDNS_SPOOFPOL_HH
#define PDNS_SPOOFPOL_HH
#include <string>
#include <sys/time.h>
#include <time.h>
#include "iputils.hh"
#include <map>

class SpoofPolicy
{
public:
  void report(const ComboAddress& remote, 
              const std::string& auth, 
              int policy,
              const struct timeval& );
  int getPolicy(const ComboAddress& remote, const std::string& aith, const struct timeval& );

private:
  struct SpoofEntry
  {
    time_t ttd;
    int policy;
  };
  typedef std::map<std::pair<ComboAddress, string>, SpoofEntry > spoofmap_t;
  spoofmap_t d_spoofmap;
};

#endif
