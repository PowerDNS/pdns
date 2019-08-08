/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/** two modes:

anonymizing and stripping tcpdumps of irrelevant traffic, so operators can send non-privacy violating dumps
for analysis.

algorithm:

read a packet, check if it has the QR bit set.

If the question has the response bit set, obfuscate the destination IP address
otherwise, obfuscate the response IP address
*/


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "statbag.hh"
#include "dnspcap.hh"
#include "iputils.hh"
#include "ipcipher.hh"
#include "namespaces.hh"
#include <boost/program_options.hpp>
#include "base64.hh"

StatBag S;

namespace po = boost::program_options;
po::variables_map g_vm;


class IPObfuscator
{
public:
  virtual ~IPObfuscator()
  {
  }
  virtual uint32_t obf4(uint32_t orig)=0;
  virtual struct in6_addr obf6(const struct in6_addr& orig)=0;
};

class IPSeqObfuscator : public IPObfuscator
{
public:
  IPSeqObfuscator() : d_romap(d_ipmap), d_ro6map(d_ip6map), d_counter(0)
  {
  }

  ~IPSeqObfuscator()
  {}

  static std::unique_ptr<IPObfuscator> make()
  {
    return std::unique_ptr<IPObfuscator>(new IPSeqObfuscator());
  }

  uint32_t obf4(uint32_t orig) override
  {
    if(d_romap.count(orig))
      return d_ipmap[orig];
    else {
      return d_ipmap[orig]=d_counter++;
    }
  }

  struct in6_addr obf6(const struct in6_addr& orig) override
  {
    uint32_t val;
    if(d_ro6map.count(orig))
      val=d_ip6map[orig];
    else {
      val=d_ip6map[orig]=d_counter++;
    }
    struct in6_addr ret;

    val=htonl(val);
    memset(&ret, 0, sizeof(ret));
    memcpy(((char*)&ret)+12, &val, 4);
    return ret;
  }

private:
  map<uint32_t, uint32_t> d_ipmap;
  const decltype(d_ipmap)& d_romap;

  struct cmp {
    bool operator()(const struct in6_addr&a , const struct in6_addr&b) const
    {
      return memcmp(&a, &b, sizeof(a)) < 0;
    }
  };
  // For IPv6 addresses
  map<struct in6_addr, uint32_t, cmp> d_ip6map;
  const decltype(d_ip6map)& d_ro6map;

  // The counter that we'll convert to an IP address
  uint32_t d_counter;
};

class IPCipherObfuscator : public IPObfuscator
{
public:
  IPCipherObfuscator(const std::string& key, bool decrypt)  : d_key(key), d_decrypt(decrypt)
  {
    if(d_key.size()!=16) {
      throw std::runtime_error("IPCipher requires a 128 bit key");
    }
  }

  ~IPCipherObfuscator()
  {}
  static std::unique_ptr<IPObfuscator> make(std::string key, bool decrypt)
  {
    return std::unique_ptr<IPObfuscator>(new IPCipherObfuscator(key, decrypt));
  }

  uint32_t obf4(uint32_t orig) override
  {
    ComboAddress ca;
    ca.sin4.sin_family = AF_INET;
    ca.sin4.sin_addr.s_addr = orig;
    ca = d_decrypt ? decryptCA(ca, d_key) : encryptCA(ca, d_key);
    return ca.sin4.sin_addr.s_addr;

  }

  struct in6_addr obf6(const struct in6_addr& orig) override
  {
    ComboAddress ca;
    ca.sin4.sin_family = AF_INET6;
    ca.sin6.sin6_addr = orig;
    ca = d_decrypt ? decryptCA(ca, d_key) : encryptCA(ca, d_key);
    return ca.sin6.sin6_addr;
  }

private:
  std::string d_key;
  bool d_decrypt;
};


void usage() {
  cerr<<"Syntax: dnswasher INFILE1 [INFILE2..] OUTFILE"<<endl;
}

int main(int argc, char** argv)
try
{
  po::options_description desc("Allowed options");
  desc.add_options()
    ("help,h", "produce help message")
    ("version", "show version number")
    ("key,k", po::value<string>(), "base64 encoded 128 bit key for ipcipher")
    ("passphrase,p", po::value<string>(), "passphrase for ipcipher (will be used to derive key)")
    ("decrypt,d", "decrypt IP addresses with ipcipher");

  po::options_description alloptions;
  po::options_description hidden("hidden options");
  hidden.add_options()
    ("infiles", po::value<vector<string>>(), "PCAP source file(s)")
    ("outfile", po::value<string>(), "outfile");


  alloptions.add(desc).add(hidden);
  po::positional_options_description p;
  p.add("infiles", 1);
  p.add("outfile", 1);

  po::store(po::command_line_parser(argc, argv).options(alloptions).positional(p).run(), g_vm);
  po::notify(g_vm);

  if(g_vm.count("help")) {
    usage();
    cout<<desc<<endl;
    exit(EXIT_SUCCESS);
  }

  if(g_vm.count("version")) {
    cout<<"dnswasher "<<VERSION<<endl;
    exit(EXIT_SUCCESS);
  }

  if(!g_vm.count("outfile")) {
    cout<<"Missing outfile"<<endl;
    usage();
    exit(EXIT_FAILURE);
  }

  bool doDecrypt = g_vm.count("decrypt");

  PcapPacketWriter pw(g_vm["outfile"].as<string>());
  std::unique_ptr<IPObfuscator> ipo;

  if(!g_vm.count("key") && !g_vm.count("passphrase"))
    ipo = IPSeqObfuscator::make();
  else if(g_vm.count("key") && !g_vm.count("passphrase")) {
    string key;
    if(B64Decode(g_vm["key"].as<string>(), key) < 0) {
      cerr<<"Invalidly encoded base64 key provided"<<endl;
      exit(EXIT_FAILURE);
    }
    ipo = IPCipherObfuscator::make(key, doDecrypt);
  }
  else if(!g_vm.count("key") && g_vm.count("passphrase")) {
    string key = makeIPCipherKey(g_vm["passphrase"].as<string>());

    ipo = IPCipherObfuscator::make(key, doDecrypt);
  }
  else {
    cerr<<"Can't specify both 'key' and 'passphrase'"<<endl;
    exit(EXIT_FAILURE);
  }

  for(const auto& inf : g_vm["infiles"].as<vector<string>>()) {
    PcapPacketReader pr(inf);
    pw.setPPR(pr);

    while(pr.getUDPPacket()) {
      if(ntohs(pr.d_udp->uh_dport)==53 || (ntohs(pr.d_udp->uh_sport)==53 && pr.d_len > sizeof(dnsheader))) {
        dnsheader* dh=(dnsheader*)pr.d_payload;

        if (pr.d_ip->ip_v == 4){
          uint32_t *src=(uint32_t*)&pr.d_ip->ip_src;
          uint32_t *dst=(uint32_t*)&pr.d_ip->ip_dst;

          if(dh->qr)
            *dst=ipo->obf4(*dst);
          else
            *src=ipo->obf4(*src);

          pr.d_ip->ip_sum=0;
        } else if (pr.d_ip->ip_v == 6) {
          auto src=&pr.d_ip6->ip6_src;
          auto dst=&pr.d_ip6->ip6_dst;

          if(dh->qr)
            *dst=ipo->obf6(*dst);
          else
            *src=ipo->obf6(*src);
          // IPv6 checksum does not cover source/destination addresses
        }
        pw.write();
      }
    }
    cerr<<"Saw "<<pr.d_correctpackets<<" correct packets, "<<pr.d_runts<<" runts, "<< pr.d_oversized<<" oversize, "<<
      pr.d_nonetheripudp<<" unknown encaps"<<endl;
  }
}
catch(std::exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
