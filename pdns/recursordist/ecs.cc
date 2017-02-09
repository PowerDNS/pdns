#include "syncres.hh"
#include "arguments.hh"

NetmaskGroup g_ednssubnets;
SuffixMatchNode g_ednsdomains;
bool g_useIncomingECS;

boost::optional<Netmask> getEDNSSubnetMask(const ComboAddress& local, const DNSName&dn, const ComboAddress& rem, boost::optional<const EDNSSubnetOpts&> incomingECS)
{
  static uint8_t l_ipv4limit, l_ipv6limit;
  if(!l_ipv4limit) {
    l_ipv4limit = ::arg().asNum("ecs-ipv4-bits");
    l_ipv6limit = ::arg().asNum("ecs-ipv6-bits");
  }
  boost::optional<Netmask> result;
  ComboAddress trunc;
  uint8_t bits;
  if(incomingECS) {
    if (incomingECS->source.getBits() == 0) {
      /* RFC7871 says we MUST NOT send any ECS if the source scope is 0 */
      return result;
    }
    trunc = incomingECS->source.getMaskedNetwork();
    bits = incomingECS->source.getBits();
  }
  else if(!local.isIPv4() || local.sin4.sin_addr.s_addr) { // detect unset 'requestor'
    trunc = local;
    bits = local.isIPv4() ? 32 : 128;
  }
  else {
    /* nothing usable */
    return result;
  }

  if(g_ednsdomains.check(dn) || g_ednssubnets.match(rem)) {
    bits = std::min(bits, (trunc.isIPv4() ? l_ipv4limit : l_ipv6limit));
    trunc.truncate(bits);
    return boost::optional<Netmask>(Netmask(trunc, bits));
  }
  return result;
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
