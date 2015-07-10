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
  bool preresolve(const ComboAddress& remote,const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSResourceRecord>& res, int& ret, bool* variable);
  bool nxdomain(const ComboAddress& remote, const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSResourceRecord>& res, int& ret, bool* variable);
  bool nodata(const ComboAddress& remote, const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSResourceRecord>& res, int& ret, bool* variable);
  bool postresolve(const ComboAddress& remote, const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSResourceRecord>& res, int& ret, bool* variable);
  bool preoutquery(const ComboAddress& ns, const ComboAddress& requestor, const DNSName& query, const QType& qtype, vector<DNSResourceRecord>& res, int& ret);
  bool ipfilter(const ComboAddress& remote, const ComboAddress& local);
private:
  bool passthrough(const string& func, const ComboAddress& remote,const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSResourceRecord>& ret, int& res, bool* variable);

  struct NoFuncs
  {
    NoFuncs() : preresolve(0), nxdomain(0), nodata(0), postresolve(0), preoutquery(0), ipfilter()
    {}
    
    void regist(const std::string& func)
    {
      if(func=="preresolve")       preresolve=1;
      else if(func=="nxdomain")    nxdomain=1;
      else if(func=="nodata")      nodata=1;
      else if(func=="postresolve") postresolve=1;
      else if(func=="preoutquery") preoutquery=1;
      else if(func=="ipfilter")    ipfilter=1;
      else throw std::runtime_error("Attempting to blacklist unknown Lua function");
      
    }

    void reset()
    {
      *this = NoFuncs();
    }
    bool preresolve, nxdomain, nodata, postresolve, preoutquery, ipfilter;
  } d_nofuncs;

};

#endif
