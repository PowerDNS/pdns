#include "syncres.hh"
#include "arguments.hh"

NetmaskGroup g_ednssubnets;
SuffixMatchNode g_ednsdomains;
bool g_useIncomingECS;

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
