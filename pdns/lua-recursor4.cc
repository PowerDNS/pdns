#include "lua-recursor4.hh"
#include <fstream>
#undef L
#include "ext/luawrapper/include/LuaContext.hpp"
#include "logger.hh"

RecursorLua4::RecursorLua4(const std::string& fname)
{
  d_lw = new LuaContext;
  d_lw->writeFunction("newDN", [](const std::string& dom){ return DNSName(dom); });  
  d_lw->registerFunction("isPartOf", &DNSName::isPartOf);  
  d_lw->registerFunction("toString", &ComboAddress::toString);  
  d_lw->registerFunction("toString", &DNSName::toString);    

  vector<pair<string,int>> pd{{"PASS", PolicyDecision::PASS}, {"DROP",  PolicyDecision::DROP}, {"TRUNCATE", PolicyDecision::TRUNCATE}};
  d_lw->writeVariable("pdns", pd);            
  
  ifstream ifs(fname);
  if(!ifs) {
    theL()<<"Unable to read configuration file from '"<<fname<<"': "<<strerror(errno)<<endl;
    return;
  }  	
  d_lw->executeCode(ifs);
}

bool RecursorLua4::preresolve(const ComboAddress& remote,const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSRecord>& res, int& ret, bool* variable)
{
  const auto function = d_lw->readVariable<std::function<bool(const ComboAddress& remote, const ComboAddress& local, const DNSName& query, uint16_t)>>("preresolve");
  if(!function)
    return false;
  ret = function(remote, local, query, qtype.getCode());
  return true;
}