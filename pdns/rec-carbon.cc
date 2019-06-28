#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "mtasker.hh"
#include "syncres.hh"
#include "rec_channel.hh"
#include "iputils.hh"
#include "logger.hh"
#include "arguments.hh"
#include "lock.hh"


void doCarbonDump(void*)
try
{
  string hostname;
  string instance_name;
  string namespace_name;
  vector<string> carbonServers;

  {
    Lock l(&g_carbon_config_lock);
    stringtok(carbonServers, arg()["carbon-server"], ", ");
    namespace_name=arg()["carbon-namespace"];
    hostname=arg()["carbon-ourname"];
    instance_name=arg()["carbon-instance"];
  }

  if(carbonServers.empty())
    return;

  if(namespace_name.empty()) {
    namespace_name="pdns";
  }
  if(hostname.empty()) {
    char tmp[80];
    memset(tmp, 0, sizeof(tmp));
    gethostname(tmp, sizeof(tmp));
    char *p = strchr(tmp, '.');
    if(p) *p=0;

    hostname=tmp;
    boost::replace_all(hostname, ".", "_");    
  }
  if(instance_name.empty()) {
    instance_name="recursor";
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
      all_t all=getAllStatsMap(StatComponent::Carbon);
      
      ostringstream str;
      time_t now=time(0);
      
      for(const all_t::value_type& val :  all) {
        str<<namespace_name<<'.'<<hostname<<'.'<<instance_name<<'.'<<val.first<<' '<<val.second<<' '<<now<<"\r\n";
      }
      msg = str.str();
    }

    int ret=asendtcp(msg, &s);     // this will actually do the right thing waiting on the connect
    if(ret < 0)
      g_log<<Logger::Warning<<"Error writing carbon data to "<<remote.toStringWithPort()<<": "<<stringerror()<<endl;
    if(ret==0)
      g_log<<Logger::Warning<<"Timeout connecting/writing carbon data to "<<remote.toStringWithPort()<<endl;
  }
 }
catch(PDNSException& e)
{
  g_log<<Logger::Error<<"Error in carbon thread: "<<e.reason<<endl;
}
catch(std::exception& e)
{
  g_log<<Logger::Error<<"Error in carbon thread: "<<e.what()<<endl;
}
catch(...)
{
  g_log<<Logger::Error<<"Unknown error in carbon thread"<<endl;
}
