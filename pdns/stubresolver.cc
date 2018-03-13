#include <sys/stat.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "logger.hh"
#include "arguments.hh"
#include "version.hh"
#include "misc.hh"

#include "sstuff.hh"
#include "dnswriter.hh"
#include "dns_random.hh"
#include "namespaces.hh"
#include "statbag.hh"
#include "stubresolver.hh"

#define LOCAL_RESOLV_CONF_PATH "/etc/resolv.conf"

// s_resolversForStub contains the ComboAddresses that are used by
// stubDoResolve
static vector<ComboAddress> s_resolversForStub;
static pthread_mutex_t s_resolversForStubLock = PTHREAD_MUTEX_INITIALIZER;

// /etc/resolv.conf last modification time
static auto s_localResolvConfMtime = 0;

/*
 * Returns false if no resolvers are configured, while emitting a warning about this
 */
bool resolversDefined()
{
  if (s_resolversForStub.empty()) {
    L<<Logger::Warning<<"No upstream resolvers configured, stub resolving (including secpoll and ALIAS) impossible."<<endl;
    return false;
  }
  return true;
}

/*
 * Parse /etc/resolv.conf and add those nameservers to s_resolversForStub
 */
static void parseLocalResolvConf()
{
  ifstream ifs(LOCAL_RESOLV_CONF_PATH);
  struct stat st;
  string line;

  if(!ifs)
    return;
  if (stat(LOCAL_RESOLV_CONF_PATH, &st) == -1)
    return ;
  s_localResolvConfMtime = st.st_mtime;

  pthread_mutex_lock(&s_resolversForStubLock);
  s_resolversForStub.clear();
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
          s_resolversForStub.push_back(ComboAddress(*iter, 53));
        }
        catch(...)
        {
        }
      }
    }
  }
  pthread_mutex_unlock(&s_resolversForStubLock);
}

/*
 * Fill the s_resolversForStub vector with addresses for the upstream resolvers.
 * First, parse the `resolver` configuration option for IP addresses to use.
 * If that doesn't work, parse /etc/resolv.conf and add those nameservers to
 * s_resolversForStub.
 */
void stubParseResolveConf()
{
  if(::arg().mustDo("resolver")) {
    vector<string> parts;
    stringtok(parts, ::arg()["resolver"], " ,\t");
    for (const auto& addr : parts)
      s_resolversForStub.push_back(ComboAddress(addr, 53));
  }

  if (s_resolversForStub.empty()) {
    parseLocalResolvConf();
  }
  // Emit a warning if there are no stubs.
  resolversDefined();
}

// s_resolversForStub contains the ComboAddresses that are used to resolve the
int stubDoResolve(const DNSName& qname, uint16_t qtype, vector<DNSZoneRecord>& ret)
{
  // only check if resolvers come from he local resolv.conf in the first place
  if (s_localResolvConfMtime != 0) {
    struct stat st;

    if (stat(LOCAL_RESOLV_CONF_PATH, &st) != -1) {
      if (st.st_mtime > s_localResolvConfMtime) {
        parseLocalResolvConf();
      }
    }
  }
  if (!resolversDefined())
    return RCode::ServFail;

  vector<uint8_t> packet;

  DNSPacketWriter pw(packet, qname, qtype);
  pw.getHeader()->id=dns_random(0xffff);
  pw.getHeader()->rd=1;

  string msg ="Doing stub resolving, using resolvers: ";
  for (const auto& server : s_resolversForStub) {
    msg += server.toString() + ", ";
  }
  L<<Logger::Debug<<msg.substr(0, msg.length() - 2)<<endl;

  for(const ComboAddress& dest :  s_resolversForStub) {
    Socket sock(dest.sin4.sin_family, SOCK_DGRAM);
    sock.setNonBlocking();
    sock.connect(dest);
    sock.send(string(packet.begin(), packet.end()));

    string reply;

    waitForData(sock.getHandle(), 2, 0);
    try {
    retry:
      sock.read(reply); // this calls recv
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
    MOADNSParser mdp(false, reply);
    if(mdp.d_header.rcode == RCode::ServFail)
      continue;

    for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {
      if(i->first.d_place == 1 && i->first.d_type==qtype) {
        DNSZoneRecord zrr;
        zrr.dr = i->first;
        zrr.auth=true;
        ret.push_back(zrr);
      }
    }
    L<<Logger::Debug<<"Question got answered by "<<dest.toString()<<endl;
    return mdp.d_header.rcode;
  }
  return RCode::ServFail;
}
