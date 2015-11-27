#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "statbag.hh"
#include "logger.hh"
#include "iputils.hh"
#include "sstuff.hh"
#include "arguments.hh"
#include "common_startup.hh"

#include "namespaces.hh"

void* carbonDumpThread(void*)
try
{
  extern StatBag S;

  for(int numloops=0;;++numloops) {
    if(arg()["carbon-server"].empty()) {
      sleep(1);
      continue;
    }
    if(numloops)
      sleep(arg().asNum("carbon-interval"));

    try {
      ComboAddress remote(arg()["carbon-server"], 2003);
      Socket s(remote.sin4.sin_family, SOCK_STREAM);
      
      s.setNonBlocking();
      s.connect(remote);  // we do the connect so the attempt happens while we gather stats
      
      vector<string> entries = S.getEntries();
      
      ostringstream str;
      time_t now=time(0);
      string hostname=arg()["carbon-ourname"];
      if(hostname.empty()) {
	char tmp[80];
	memset(tmp, 0, sizeof(tmp));
	gethostname(tmp, sizeof(tmp));
	char *p = strchr(tmp, '.');
	if(p) *p=0;
	hostname=tmp;
	boost::replace_all(hostname, ".", "_");
      }
      for(const string& entry :  entries) {
	str<<"pdns."<<hostname<<".auth."<<entry<<' '<<S.read(entry)<<' '<<now<<"\r\n";
      }
      const string msg = str.str();
      
      int ret = waitForRWData(s.getHandle(), false, 1 , 0); 
      if(ret <= 0 ) {
	L<<Logger::Warning<<"Unable to write data to carbon server on "<<remote.toStringWithPort();
	L<<": "<< (ret<0 ? strerror(errno) : "Timeout")<<endl;
	continue;
      }
      s.setBlocking();
      ret=writen2(s.getHandle(), msg.c_str(), msg.size());
      if(ret < 0)
	L<<Logger::Warning<<"Error writing carbon data to "<<remote.toStringWithPort()<<": "<<strerror(errno)<<endl;
      if(ret==0)
	L<<Logger::Warning<<"EOF writing carbon data to "<<remote.toStringWithPort()<<endl;
    }
    catch(std::exception& e) {
      L<<Logger::Warning<<"Problem sending carbon data: "<<e.what()<<endl;
    }
  }
  return 0;
}
catch(std::exception& e)
{
  L<<Logger::Error<<"Carbon thread died: "<<e.what()<<endl;
  return 0;
}
catch(PDNSException& e)
{
  L<<Logger::Error<<"Carbon thread died, PDNSException: "<<e.reason<<endl;
  return 0;
}
catch(...)
{
  L<<Logger::Error<<"Carbon thread died"<<endl;
  return 0;
}
