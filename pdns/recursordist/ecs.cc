#include "syncres.hh"
#include "arguments.hh"

NetmaskGroup g_ednssubnets;
SuffixMatchNode g_ednsdomains;

boost::optional<Netmask> getEDNSSubnetMask(const ComboAddress& local, const DNSName&dn, const ComboAddress& rem)
{
  static int l_ipv4limit, l_ipv6limit;
  if(!l_ipv4limit) {
    l_ipv4limit = ::arg().asNum("ecs-ipv4-bits");
    l_ipv6limit = ::arg().asNum("ecs-ipv6-bits");
  }
  if(local.sin4.sin_family != AF_INET || local.sin4.sin_addr.s_addr) { // detect unset 'requestor'
    if(g_ednsdomains.check(dn) || g_ednssubnets.match(rem)) {
      int bits = local.sin4.sin_family == AF_INET ? l_ipv4limit : l_ipv6limit;
      ComboAddress trunc(local);
      trunc.truncate(bits);
      return boost::optional<Netmask>(Netmask(trunc, bits));
    }
  }
  return boost::optional<Netmask>();
}

void  parseEDNSSubnetWhitelist(const std::string& wlist)
{
  vector<string> parts;
  stringtok(parts, wlist, ",; ");
  for(const auto& a : parts) {
    try {
      Netmask nm(a);
      g_ednssubnets.addMask(nm);
    }
    catch(...) {
      g_ednsdomains.add(DNSName(a));
    }
  }
}
