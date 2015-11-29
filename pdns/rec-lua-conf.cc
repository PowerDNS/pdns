#include "ext/luawrapper/include/LuaContext.hpp"
#include <fstream>
#include "namespaces.hh"
#include "logger.hh"
#include "sortlist.hh"

SortList g_sortlist;
void loadRecursorLuaConfig(const std::string& fname)
{
  LuaContext Lua;
  if(fname.empty())
    return;
  ifstream ifs(fname);
  if(!ifs) {
    theL()<<"Unable to read configuration file from '"<<fname<<"': "<<strerror(errno)<<endl;
    return;
  }
  Lua.writeFunction("clearSortlist", []() { g_sortlist.clear(); });
  
  /* we can get: "1.2.3.4"
                 {"1.2.3.4", "4.5.6.7"}
		 {"1.2.3.4", {"4.5.6.7", "8.9.10.11"}}
  */

  typedef vector<pair<int,boost::variant<string, vector<pair<int, string> > > > > argvec_t;
  Lua.writeFunction("addSortList", 
		    [](const std::string& formask_, 
		       const boost::variant<string, argvec_t>& masks,
		       boost::optional<int> order_) 
		    {
		      try {
			Netmask formask(formask_);
			int order = order_ ? (*order_) : g_sortlist.getMaxOrder(formask)+1;
			if(auto str = boost::get<string>(&masks)) 
			  g_sortlist.addEntry(formask, Netmask(*str), order);
			else {
	
			  auto vec = boost::get<argvec_t>(&masks);
			  for(const auto& e : *vec) {
			    if(auto s = boost::get<string>(&e.second)) {
			      g_sortlist.addEntry(formask, Netmask(*s), order);
			    }
			    else {
			      const auto& v =boost::get<vector<pair<int, string> > >(e.second);
			      for(const auto& e : v)
				g_sortlist.addEntry(formask, Netmask(e.second), order);
			    }
			    ++order;
			  }
			}
		      }
		      catch(std::exception& e) {
			theL()<<Logger::Error<<"Error in addSortList: "<<e.what()<<endl;
		      }
		    });
  Lua.executeCode(ifs);
  
}
