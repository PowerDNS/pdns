#ifndef PDNS_LUA_RECURSOR_HH
#define PDNS_LUA_RECURSOR_HH
#include "dns.hh"
#include "iputils.hh"
#include "lua-pdns.hh"

class RecursorLua : public PowerDNSLua
{
public:
  explicit RecursorLua(const std::string& fname);
  // ~RecursorLua();
  bool preresolve(const ComboAddress& remote,const ComboAddress& local, const string& query, const QType& qtype, vector<DNSResourceRecord>& res, int& ret, bool* variable);
  bool nxdomain(const ComboAddress& remote, const ComboAddress& local, const string& query, const QType& qtype, vector<DNSResourceRecord>& res, int& ret, bool* variable);
  bool nodata(const ComboAddress& remote, const ComboAddress& local, const string& query, const QType& qtype, vector<DNSResourceRecord>& res, int& ret, bool* variable);
  bool postresolve(const ComboAddress& remote, const ComboAddress& local, const string& query, const QType& qtype, vector<DNSResourceRecord>& res, int& ret, bool* variable);

private:
  bool passthrough(const string& func, const ComboAddress& remote,const ComboAddress& local, const string& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res, bool* variable);
};

#endif
