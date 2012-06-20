#ifndef PDNS_LUA_AUTH_HH
#define PDNS_LUA_AUTH_HH
#include "dns.hh"
#include "iputils.hh"
#include "dnspacket.hh"
#include "lua-pdns.hh"

class AuthLua : public PowerDNSLua
{
public:
  explicit AuthLua(const std::string& fname);
  // ~AuthLua();
  bool axfrfilter(const ComboAddress& remote, const string& zone, const DNSResourceRecord& in, vector<DNSResourceRecord>& out);
  DNSPacket* prequery(DNSPacket *p);

private:
  void registerLuaDNSPacket(void);
};

#endif
