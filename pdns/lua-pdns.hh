#ifndef PDNS_LUA_PDNS_HH
#define PDNS_LUA_PDNS_HH
#include "dns.hh"
#include "iputils.hh"

struct lua_State;

class PowerDNSLua
{
public:
  explicit PowerDNSLua(const std::string& fname);
  ~PowerDNSLua();
  void reload();
  ComboAddress getLocal()
  {
    return d_local;
  }

  void setVariable()
  {
    d_variable=true;
  }

protected: // FIXME?
  lua_State* d_lua;
  bool passthrough(const string& func, const ComboAddress& remote,const ComboAddress& local, const string& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res, bool* variable);
  bool getFromTable(const std::string& key, std::string& value);
  bool getFromTable(const std::string& key, uint32_t& value);
  bool d_failed;
  bool d_variable;  
  ComboAddress d_local;
};

void pushResourceRecordsTable(lua_State* lua, const vector<DNSResourceRecord>& records);
void popResourceRecordsTable(lua_State *lua, const string &query, vector<DNSResourceRecord>& ret);
int getLuaTableLength(lua_State* lua, int depth);
#endif
