#pragma once
#include "iputils.hh"
#include "dnsname.hh"
#include "namespaces.hh"

class LuaContext;
class RecursorLua4
{
public:
  explicit RecursorLua4(const std::string& fname);
  // ~RecursorLua();
  bool preresolve(const ComboAddress& remote,const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSRecord>& res, int& ret, bool* variable);
private:
  LuaContext* d_lw;
};

