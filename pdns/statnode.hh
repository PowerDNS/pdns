#pragma once
#include "dnsname.hh"
#include <deque>
#include <map>
#include "iputils.hh"

class StatNode
{
public:
  void submit(const DNSName& domain, int rcode, const ComboAddress& remote);
  void submit(std::deque<std::string>& labels, const std::string& domain, int rcode, const ComboAddress& remote);

  std::string name;
  std::string fullname;
  struct Stat 
  {
    Stat() : queries(0), noerrors(0), nxdomains(0), servfails(0), drops(0){}
    int queries, noerrors, nxdomains, servfails, drops;

    Stat& operator+=(const Stat& rhs) {
      queries+=rhs.queries;
      noerrors+=rhs.noerrors;
      nxdomains+=rhs.nxdomains;
      servfails+=rhs.servfails;
      drops+=rhs.drops;

      for(const remotes_t::value_type& rem :  rhs.remotes) {
	remotes[rem.first]+=rem.second;
      }
      return *this;
    }
typedef std::map<ComboAddress,int,ComboAddress::addressOnlyLessThan> remotes_t;
    remotes_t remotes;
  };

  Stat s;
  Stat print(int depth=0, Stat newstat=Stat(), bool silent=false) const;
  typedef boost::function<void(const StatNode*, const Stat& selfstat, const Stat& childstat)> visitor_t;
  void visit(visitor_t visitor, Stat& newstat, int depth=0) const;
  typedef std::map<std::string,StatNode, CIStringCompare> children_t;
  children_t children;
  
};
