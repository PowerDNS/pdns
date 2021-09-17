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
// don't stat() for local resolv.conf more than once every INTERVAL secs.
#define LOCAL_RESOLV_CONF_MAX_CHECK_INTERVAL 60

// s_resolversForStub contains the ComboAddresses that are used by
// stubDoResolve
static SharedLockGuarded<vector<ComboAddress>> s_resolversForStub;
static bool s_stubResolvConfigured = false;

// /etc/resolv.conf last modification time
static time_t s_localResolvConfMtime = 0;
static time_t s_localResolvConfLastCheck = 0;

static string logPrefix = "[stub-resolver] ";

/*
 * Returns false if no resolvers are configured, while emitting a warning about this
 */
bool resolversDefined()
{
  if (s_resolversForStub.read_lock()->empty()) {
    g_log<<Logger::Warning<<logPrefix<<"No upstream resolvers configured, stub resolving (including secpoll and ALIAS) impossible."<<endl;
    return false;
  }
  return true;
}

/*
 * Parse /etc/resolv.conf and add those nameservers to s_resolversForStub
 */
static void parseLocalResolvConf_locked(vector<ComboAddress>& resolversForStub, const time_t& now)
{
  struct stat st;
  s_localResolvConfLastCheck = now;

  if (stat(LOCAL_RESOLV_CONF_PATH, &st) != -1) {
    if (st.st_mtime != s_localResolvConfMtime) {
      std::vector<ComboAddress> resolvers = getResolvers(LOCAL_RESOLV_CONF_PATH);

      s_localResolvConfMtime = st.st_mtime;

      if (resolvers.empty()) {
        return;
      }

      resolversForStub = std::move(resolvers);
    }
  }
}

static void parseLocalResolvConf()
{
  const time_t now = time(nullptr);
  if ((s_localResolvConfLastCheck + LOCAL_RESOLV_CONF_MAX_CHECK_INTERVAL) > now)
    return ;

  parseLocalResolvConf_locked(*(s_resolversForStub.write_lock()), now);
}


/*
 * Fill the s_resolversForStub vector with addresses for the upstream resolvers.
 * First, parse the `resolver` configuration option for IP addresses to use.
 * If that doesn't work, parse /etc/resolv.conf and add those nameservers to
 * s_resolversForStub.
 *
 * mainthread() calls this so you don't have to.
 */
void stubParseResolveConf()
{
  if(::arg().mustDo("resolver")) {
    auto resolversForStub = s_resolversForStub.write_lock();
    vector<string> parts;
    stringtok(parts, ::arg()["resolver"], " ,\t");
    for (const auto& addr : parts)
      resolversForStub->push_back(ComboAddress(addr, 53));
  }

  if (s_resolversForStub.read_lock()->empty()) {
    parseLocalResolvConf();
  }
  // Emit a warning if there are no stubs.
  resolversDefined();
  s_stubResolvConfigured = true;
}

// s_resolversForStub contains the ComboAddresses that are used to resolve the
int stubDoResolve(const DNSName& qname, uint16_t qtype, vector<DNSZoneRecord>& ret)
{
  // ensure resolver gets always configured
  if (!s_stubResolvConfigured) {
    stubParseResolveConf();
  }
  // only check if resolvers come from local resolv.conf in the first place
  if (s_localResolvConfMtime != 0) {
        parseLocalResolvConf();
  }
  if (!resolversDefined())
    return RCode::ServFail;

  auto resolversForStub = s_resolversForStub.read_lock();
  vector<uint8_t> packet;

  DNSPacketWriter pw(packet, qname, qtype);
  pw.getHeader()->id=dns_random_uint16();
  pw.getHeader()->rd=1;

  string queryNameType = qname.toString() + "|" + QType(qtype).toString();
  string msg ="Doing stub resolving for '" + queryNameType + "', using resolvers: ";
  for (const auto& server : *resolversForStub) {
    msg += server.toString() + ", ";
  }
  g_log<<Logger::Debug<<logPrefix<<msg.substr(0, msg.length() - 2)<<endl;

  for(const ComboAddress& dest : *resolversForStub) {
    Socket sock(dest.sin4.sin_family, SOCK_DGRAM);
    sock.setNonBlocking();
    sock.connect(dest);
    sock.send(string(packet.begin(), packet.end()));

    string reply;

    // error handled after this
    (void)waitForData(sock.getHandle(), 2, 0);
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

    for(const auto & answer : mdp.d_answers) {
      if(answer.first.d_place == 1 && answer.first.d_type==qtype) {
        DNSZoneRecord zrr;
        zrr.dr = answer.first;
        zrr.auth=true;
        ret.push_back(zrr);
      }
    }
    g_log<<Logger::Debug<<logPrefix<<"Question for '"<<queryNameType<<"' got answered by "<<dest.toString()<<endl;
    return mdp.d_header.rcode;
  }
  return RCode::ServFail;
}

int stubDoResolve(const DNSName& qname, uint16_t qtype, vector<DNSRecord>& ret) {
  vector<DNSZoneRecord> ret2;
  int res = stubDoResolve(qname, qtype, ret2);
  for (const auto &r : ret2) {
    ret.push_back(r.dr);
  }
  return res;
}
