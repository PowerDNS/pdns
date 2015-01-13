#include "secpoll-auth.hh"

#include "logger.hh"
#include "arguments.hh"
#include "version.hh"
#include "version_generated.h"
#include "dnsparser.hh"
#include "misc.hh"
#include <boost/foreach.hpp>
#include "sstuff.hh"
#include "dnswriter.hh"
#include "dns_random.hh"
#include "namespaces.hh"
#include "statbag.hh"
#include <stdint.h>
#ifndef PACKAGEVERSION 
#define PACKAGEVERSION PDNS_VERSION
#endif

string g_security_message;

extern StatBag S;

static vector<ComboAddress> parseResolveConf()
{
  vector<ComboAddress> ret;
  ifstream ifs("/etc/resolv.conf");
  if(!ifs)
    return ret;

  string line;
  while(std::getline(ifs, line)) {
    boost::trim_right_if(line, is_any_of(" \r\n\x1a"));
    boost::trim_left(line); // leading spaces, let's be nice

    string::size_type tpos = line.find_first_of(";#");
    if(tpos != string::npos)
      line.resize(tpos);

    if(boost::starts_with(line, "nameserver ") || boost::starts_with(line, "nameserver\t")) {
      vector<string> parts;
      stringtok(parts, line, " \t,"); // be REALLY nice
      for(vector<string>::const_iterator iter = parts.begin()+1; iter != parts.end(); ++iter) {
	
	try {
	  ret.push_back(ComboAddress(*iter, 53));
	}
	catch(...)
	{
	}
      }
    }

  }

  return ret;
}

int doResolve(const string& qname, uint16_t qtype, vector<DNSResourceRecord>& ret) 
{
  vector<uint8_t> packet;

  DNSPacketWriter pw(packet, qname, qtype);
  pw.getHeader()->id=dns_random(0xffff);
  pw.getHeader()->rd=1;

  static vector<ComboAddress> s_servers;
  vector<ComboAddress> servers = parseResolveConf();
  if(!servers.empty())
    s_servers = servers; // in case we chrooted in the meantime

  if(s_servers.empty())
    L<<Logger::Warning<<"Unable to poll PowerDNS security status, did not get any servers from resolv.conf"<<endl;

  BOOST_FOREACH(ComboAddress& dest, s_servers) {
    Socket sock(dest.sin4.sin_family, SOCK_DGRAM);
    sock.setNonBlocking();
    sock.sendTo(string((char*)&*packet.begin(), (char*)&*packet.end()), dest);
    
    string reply;

    waitForData(sock.getHandle(), 2, 0);
    try {
    retry:
      sock.recvFrom(reply, dest);
      if(reply.size() > sizeof(struct dnsheader)) {
	struct dnsheader d;
	memcpy(&d, reply.c_str(), sizeof(d));
	if(d.id != pw.getHeader()->id)
	  goto retry;
      }
    }
    catch(...) {
      continue;
    }
    MOADNSParser mdp(reply);
    if(mdp.d_header.rcode == RCode::ServFail)
      continue;    
    

    for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {          
      if(i->first.d_place == 1 && i->first.d_type==QType::TXT) {
	DNSResourceRecord rr;
	rr.qname = i->first.d_label;
	rr.qtype = QType(i->first.d_type);
	rr.content = i->first.d_content->getZoneRepresentation();
	rr.ttl=i->first.d_ttl;
	ret.push_back(rr);
      }
    }
   
    return mdp.d_header.rcode;
  }
  return RCode::ServFail;
}

void doSecPoll(bool first)
{
  if(::arg()["security-poll-suffix"].empty())
    return;

  struct timeval now;
  gettimeofday(&now, 0);

  string version = "auth-" + string(PACKAGEVERSION);
  string query = version.substr(0, 63) +".security-status."+::arg()["security-poll-suffix"];

  if(*query.rbegin()!='.')
    query+='.';

  boost::replace_all(query, "+", "_");
  boost::replace_all(query, "~", "_");

  vector<DNSResourceRecord> ret;

  int res=doResolve(query, QType::TXT, ret);

  int security_status=0;

  if(!res && !ret.empty()) {
    string content=ret.begin()->content;
    if(!content.empty() && content[0]=='"' && content[content.size()-1]=='"') {
      content=content.substr(1, content.length()-2);
    }
      
    pair<string, string> split = splitField(content, ' ');
    
    security_status = atoi(split.first.c_str());
    g_security_message = split.second;

  }
  else {
    L<<Logger::Warning<<"Could not retrieve security status update for '"<<PACKAGEVERSION<<"' on '"+query+"', RCODE = "<< RCode::to_s(res)<<endl;
    if(security_status == 1) // it was ok, not it is unknown
      security_status = 0;
  }

  if(security_status == 1 && first) {
    L<<Logger::Warning << "Polled security status of version "<<PACKAGEVERSION<<" at startup, no known issues reported: " <<g_security_message<<endl;
  }
  if(security_status == 2) {
    L<<Logger::Error<<"PowerDNS Security Update Recommended: "<<g_security_message<<endl;
  }
  else if(security_status == 3) {
    L<<Logger::Error<<"PowerDNS Security Update Mandatory: "<<g_security_message<<endl;
  }

  S.set("security-status",security_status);

}
