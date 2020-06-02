#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "syncres.hh"
#include "mtasker.hh"
#include "rec_channel.hh"
#include "iputils.hh"
#include "logger.hh"
#include "arguments.hh"
#include "lock.hh"


void doCarbonDump(void*)
try
{
  string hostname;
  vector<string> carbonServers;

  {
    Lock l(&g_carbon_config_lock);
    stringtok(carbonServers, arg()["carbon-server"], ", ");
    hostname=arg()["carbon-ourname"];
  }

  if(carbonServers.empty())
    return;

  if (hostname.empty()) {
    try {
      hostname = getCarbonHostName();
    }
    catch(const std::exception& e) {
      throw std::runtime_error(std::string("The 'carbon-ourname' setting has not been set and we are unable to determine the system's hostname: ") + e.what());
    }
  }

  registerAllStats();
  string msg;
  for(const auto& carbonServer: carbonServers) {
    ComboAddress remote(carbonServer, 2003);
    Socket s(remote.sin4.sin_family, SOCK_STREAM);

    s.setNonBlocking();
    s.connect(remote);  // we do the connect so the first attempt happens while we gather stats
 
    if(msg.empty()) {
      typedef map<string,string> all_t;
      all_t all=getAllStatsMap();
      
      ostringstream str;
      time_t now=time(0);
      
      for(const all_t::value_type& val :  all) {
        str<<"pdns."<<hostname<<".recursor."<<val.first<<' '<<val.second<<' '<<now<<"\r\n";
      }
      msg = str.str();
    }

    int ret=asendtcp(msg, &s);     // this will actually do the right thing waiting on the connect
    if(ret < 0)
      L<<Logger::Warning<<"Error writing carbon data to "<<remote.toStringWithPort()<<": "<<strerror(errno)<<endl;
    if(ret==0)
      L<<Logger::Warning<<"Timeout connecting/writing carbon data to "<<remote.toStringWithPort()<<endl;
  }
 }
catch(PDNSException& e)
{
  L<<Logger::Error<<"Error in carbon thread: "<<e.reason<<endl;
}
catch(std::exception& e)
{
  L<<Logger::Error<<"Error in carbon thread: "<<e.what()<<endl;
}
catch(...)
{
  L<<Logger::Error<<"Unknown error in carbon thread"<<endl;
}
