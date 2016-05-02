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

// s_stubresolvers contains the ComboAddresses that are used by
// stubDoResolve
static vector<ComboAddress> s_stubresolvers;

/** Parse /etc/resolv.conf and add the nameservers to the vector
 * s_stubresolvers.
 */
void stubParseResolveConf()
{
  ifstream ifs("/etc/resolv.conf");
  if(!ifs)
    return;

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
          s_stubresolvers.push_back(ComboAddress(*iter, 53));
        }
        catch(...)
        {
        }
      }
    }
  }

  if(::arg().mustDo("recursor"))
    s_stubresolvers.push_back(ComboAddress(::arg()["recursor"], 53));

  // Last resort, add 127.0.0.1
  if(s_stubresolvers.empty()) {
    s_stubresolvers.push_back(ComboAddress("127.0.0.1", 53));
  }
}

// s_stubresolvers contains the ComboAddresses that are used to resolve the
int stubDoResolve(const string& qname, uint16_t qtype, vector<DNSResourceRecord>& ret)
{
  vector<uint8_t> packet;

  DNSPacketWriter pw(packet, DNSName(qname), qtype);
  pw.getHeader()->id=dns_random(0xffff);
  pw.getHeader()->rd=1;
  if (s_stubresolvers.empty()) {
    L<<Logger::Warning<<"No recursors set, stub resolving (including secpoll and ALIAS) impossible."<<endl;
    return RCode::ServFail;
  }

  string msg ="Doing stub resolving, using resolvers: ";
  for (const auto& server : s_stubresolvers) {
    msg += server.toString() + ", ";
  }
  L<<Logger::Debug<<msg.substr(0, msg.length() - 2)<<endl;

  for(ComboAddress& dest :  s_stubresolvers) {
    Socket sock(dest.sin4.sin_family, SOCK_DGRAM);
    sock.setNonBlocking();
    sock.sendTo(string(packet.begin(), packet.end()), dest);

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
      if(i->first.d_place == 1 && i->first.d_type==qtype) {
        DNSResourceRecord rr;
        rr.qname = i->first.d_name;
        rr.qtype = QType(i->first.d_type);
        rr.content = i->first.d_content->getZoneRepresentation();
        rr.ttl=i->first.d_ttl;
        ret.push_back(rr);
      }
    }
    L<<Logger::Debug<<"Question got answered by "<<dest.toString()<<endl;
    return mdp.d_header.rcode;
  }
  return RCode::ServFail;
}