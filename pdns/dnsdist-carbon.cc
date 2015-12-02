#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "iputils.hh"
#include "dolog.hh"
#include "sstuff.hh"

#include "namespaces.hh"
#undef L
#include "dnsdist.hh"

GlobalStateHolder<CarbonConfig> g_carbon;
static time_t s_start=time(0);
uint64_t uptimeOfProcess(const std::string& str)
{
  return time(0) - s_start;
}

void* carbonDumpThread()
try
{
  auto localCarbon = g_carbon.getLocal();
  for(int numloops=0;;++numloops) {
    if(localCarbon->server == ComboAddress("0.0.0.0", 0)) {
      sleep(1);
      continue;
    }
    if(numloops) 
      sleep(localCarbon->interval);

    try {
      Socket s(localCarbon->server.sin4.sin_family, SOCK_STREAM);
      
      s.setNonBlocking();
      s.connect(localCarbon->server);  // we do the connect so the attempt happens while we gather stats
      
      ostringstream str;
      time_t now=time(0);
      string hostname=localCarbon->ourname;
      if(hostname.empty()) {
	char tmp[80];
	memset(tmp, 0, sizeof(tmp));
	gethostname(tmp, sizeof(tmp));
	char *p = strchr(tmp, '.');
	if(p) *p=0;
	hostname=tmp;
	boost::replace_all(hostname, ".", "_");
      }
      for(const auto& e : g_stats.entries) {
	str<<"dnsdist."<<hostname<<".main."<<e.first<<' ';
	if(const auto& val = boost::get<DNSDistStats::stat_t*>(&e.second))
	  str<<(*val)->load();
	else if (const auto& val = boost::get<double*>(&e.second))
	  str<<**val;
	else
	  str<<(*boost::get<DNSDistStats::statfunction_t>(&e.second))(e.first);
	str<<' '<<now<<"\r\n";
      }
      const auto states = g_dstates.getCopy();
      for(const auto& s : states) {
        string serverName = s->getName();
        boost::replace_all(serverName, ".", "_");
        const string base = "dnsdist." + hostname + ".main.servers." + serverName + ".";
        str<<base<<"queries" << ' ' << s->queries.load() << " " << now << "\r\n";
        str<<base<<"drops" << ' ' << s->reuseds.load() << " " << now << "\r\n";
        str<<base<<"latency" << ' ' << s->latencyUsec/1000.0 << " " << now << "\r\n";
        str<<base<<"senderrors" << ' ' << s->sendErrors.load() << " " << now << "\r\n";
        str<<base<<"outstanding" << ' ' << s->outstanding.load() << " " << now << "\r\n";
      }
      for(const auto& front : g_frontends) {
        if (front->udpFD == -1 && front->tcpFD == -1)
          continue;

        string frontName = front->local.toStringWithPort() + (front->udpFD >= 0 ? "_udp" : "_tcp");
        boost::replace_all(frontName, ".", "_");
        const string base = "dnsdist." + hostname + ".main.frontends." + frontName + ".";
        str<<base<<"queries" << ' ' << front->queries.load() << " " << now << "\r\n";
      }
      const string msg = str.str();

      int ret = waitForRWData(s.getHandle(), false, 1 , 0); 
      if(ret <= 0 ) {
	infolog("Unable to write data to carbon server on %s: %s", localCarbon->server.toStringWithPort(), (ret<0 ? strerror(errno) : "Timeout"));
	continue;
      }
      s.setBlocking();
      ret=writen2(s.getHandle(), msg.c_str(), msg.size());
      if(ret < 0)
	warnlog("Error writing carbon data to %s: %s", localCarbon->server.toStringWithPort(), strerror(errno));
      if(ret==0)
	warnlog("EOF writing carbon data to %s", localCarbon->server.toStringWithPort());
    }
    catch(std::exception& e) {
      warnlog("Problem sending carbon data: %s", e.what());
    }
  }
  return 0;
}
catch(std::exception& e)
{
  errlog("Carbon thread died: %s", e.what());
  return 0;
}
catch(PDNSException& e)
{
  errlog("Carbon thread died, PDNSException: %s", e.reason);
  return 0;
}
catch(...)
{
  errlog("Carbon thread died");
  return 0;
}
