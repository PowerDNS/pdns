#include "secpoll-recursor.hh"
#include "syncres.hh"
#include "logger.hh"
#include "arguments.hh"

#ifndef PACKAGEVERSION 
#define PACKAGEVERSION VERSION
#endif

uint32_t g_security_status;
string g_security_message;

void doSecPoll(time_t* last_secpoll)
{
  if(::arg()["security-poll-suffix"].empty())
    return;

  struct timeval now;
  gettimeofday(&now, 0);
  SyncRes sr(now);
  
  vector<DNSResourceRecord> ret;

  int res=sr.beginResolve("recursor-" PACKAGEVERSION ".security-status."+::arg()["security-poll-suffix"], QType(QType::TXT), 1, ret);
  if(!res && !ret.empty()) {
    string content=ret.begin()->content;
    if(!content.empty() && content[0]=='"' && content[content.size()-1]=='"') {
      content=content.substr(1, content.length()-2);
    }
      
    pair<string, string> split = splitField(content, ' ');
    
    g_security_status = atoi(split.first.c_str());
    g_security_message = split.second;

    *last_secpoll=now.tv_sec;
  }
  else {
    L<<Logger::Warning<<"Could not retrieve security status update for '" PACKAGEVERSION "', RCODE = "<< RCode::to_s(res)<<endl;
    if(g_security_status == 1)
      g_security_status = 0;
  }

  if(g_security_status == 2) {
    L<<Logger::Error<<"PowerDNS Security Update Recommended: "<<g_security_message<<endl;
  }
  else if(g_security_status == 3) {
    L<<Logger::Error<<"PowerDNS Security Update Mandatory: "<<g_security_message<<endl;
  }
}
