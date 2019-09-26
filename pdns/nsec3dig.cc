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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include "base32.hh"
#include "dnssecinfra.hh"


StatBag S;

typedef std::pair<string,string> nsec3;
typedef set<nsec3> nsec3set;

string nsec3Hash(const DNSName &qname, const string &salt, unsigned int iters)
{
  NSEC3PARAMRecordContent ns3prc;
  ns3prc.d_iterations = iters;
  ns3prc.d_salt = salt;
  return toBase32Hex(hashQNameWithSalt(ns3prc, qname));
}

void proveOrDeny(const nsec3set &nsec3s, const DNSName &qname, const string &salt, unsigned int iters, set<DNSName> &proven, set<DNSName> &denied)
{
  string hashed = nsec3Hash(qname, salt, iters);

  // cerr<<"proveOrDeny(.., '"<<qname<<"', ..)"<<endl;
  // cerr<<"hashed: "<<hashed<<endl;
  for(nsec3set::const_iterator pos=nsec3s.begin(); pos != nsec3s.end(); ++pos) {
    string base=(*pos).first;
    string next=(*pos).second;

    if(hashed == base)
    {
      proven.insert(qname);
      cout<<qname.toString()<<" ("<<hashed<<") proven by base of "<<base<<".."<<next<<endl;
    }
    if(hashed == next)
    {
      proven.insert(qname);
      cout<<qname.toString()<<" ("<<hashed<<") proven by next of "<<base<<".."<<next<<endl;
    }
    if((hashed > base && hashed < next) ||
       (next < base && (hashed < next || hashed > base)))
    {
      denied.insert(qname);
      cout<<qname.toString()<<" ("<<hashed<<") denied by "<<base<<".."<<next<<endl;
    }
    if (base == next && base != hashed)
    {
      denied.insert(qname);
      cout<<qname.toString()<<" ("<<hashed<<") denied by "<<base<<".."<<next<<endl;
    }
  }
}

void usage() {
  cerr<<"nsec3dig"<<endl;
  cerr<<"Syntax: nsec3dig IP-ADDRESS PORT QUESTION QUESTION-TYPE [recurse]\n";
}

int main(int argc, char** argv)
try
{
  bool recurse=false;

  reportAllTypes();

  for (int i = 1; i < argc; i++) {
    if ((string) argv[i] == "--help") {
      usage();
      return EXIT_SUCCESS;
    }

    if ((string) argv[i] == "--version") {
      cerr<<"nsec3dig "<<VERSION<<endl;
      return EXIT_SUCCESS;
    }
  }

  if(argc < 5) {
    usage();
    exit(EXIT_FAILURE);
  }

  // FIXME: turn recurse and dnssec into proper flags or something
  if(argc > 5 && strcmp(argv[5], "recurse")==0)
  {
    recurse=true;
  }

  vector<uint8_t> packet;
  DNSName qname(argv[3]);
  DNSPacketWriter pw(packet, qname, DNSRecordContent::TypeToNumber(argv[4]));

  if(recurse)
  {
    pw.getHeader()->rd=true;
    pw.getHeader()->cd=true;
  }

  pw.addOpt(2800, 0, EDNSOpts::DNSSECOK);
  pw.commit();


  ComboAddress dest(argv[1] + (*argv[1]=='@'), atoi(argv[2]));
  Socket sock(dest.sin4.sin_family, SOCK_STREAM);  
  sock.connect(dest);
  uint16_t len;
  len = htons(packet.size());
  if(sock.write((char *) &len, 2) != 2)
    throw PDNSException("tcp write failed");

  sock.writen(string(packet.begin(), packet.end()));
  
  if(sock.read((char *) &len, 2) != 2)
    throw PDNSException("tcp read failed");

  len=ntohs(len);
  std::unique_ptr<char[]> creply(new char[len]);
  int n=0;
  int numread;
  while(n<len) {
    numread=sock.read(creply.get()+n, len-n);
    if(numread<0)
      throw PDNSException("tcp read failed");
    n+=numread;
  }

  string reply(creply.get(), len);

  MOADNSParser mdp(false, reply);
  cout<<"Reply to question for qname='"<<mdp.d_qname<<"', qtype="<<DNSRecordContent::NumberToType(mdp.d_qtype)<<endl;
  cout<<"Rcode: "<<mdp.d_header.rcode<<", RD: "<<mdp.d_header.rd<<", QR: "<<mdp.d_header.qr;
  cout<<", TC: "<<mdp.d_header.tc<<", AA: "<<mdp.d_header.aa<<", opcode: "<<mdp.d_header.opcode<<endl;

  set<DNSName> names;
  set<DNSName> namesseen;
  set<DNSName> namestocheck;
  nsec3set nsec3s;
  string nsec3salt;
  int nsec3iters = 0;
  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {     
    if(i->first.d_type == QType::NSEC3)
    {
      // cerr<<"got nsec3 ["<<i->first.d_name<<"]"<<endl;
      // cerr<<i->first.d_content->getZoneRepresentation()<<endl;
      const auto r = std::dynamic_pointer_cast<NSEC3RecordContent>(i->first.d_content);
      if (!r) {
        continue;
      }
      // nsec3.insert(new nsec3()
      // cerr<<toBase32Hex(r.d_nexthash)<<endl;
      vector<string> parts;
      string sname=i->first.d_name.toString();
      boost::split(parts, sname /* FIXME400 */, boost::is_any_of("."));
      nsec3s.insert(make_pair(toLower(parts[0]), toBase32Hex(r->d_nexthash)));
      nsec3salt = r->d_salt;
      nsec3iters = r->d_iterations;
    }
    else
    {
      // cerr<<"namesseen.insert('"<<i->first.d_name<<"')"<<endl;
      names.insert(i->first.d_name);
      namesseen.insert(i->first.d_name);
    }

    if(i->first.d_type == QType::CNAME)
    {
      namesseen.insert(DNSName(i->first.d_content->getZoneRepresentation()));
    }

    cout<<i->first.d_place-1<<"\t"<<i->first.d_name.toString()<<"\tIN\t"<<DNSRecordContent::NumberToType(i->first.d_type);
    cout<<"\t"<<i->first.d_ttl<<"\t"<< i->first.d_content->getZoneRepresentation()<<"\n";
  }

#if 0
  cerr<<"got "<<names.size()<<" names"<<endl;
  for(set<string>::const_iterator pos=names.begin(); pos != names.end(); ++pos) {
    cerr<<"name: "<<*pos<<endl;
  }
  cerr<<"got "<<nsec3s.size()<<" names"<<endl;
  for(nsec3set::const_iterator pos=nsec3s.begin(); pos != nsec3s.end(); ++pos) {
    cerr<<"nsec3: "<<(*pos).first<<".."<<(*pos).second<<endl;
  }
#endif

  cout<<"== nsec3 prove/deny report follows =="<<endl;
  set<DNSName> proven;
  set<DNSName> denied;
  namesseen.insert(qname);
  for(const auto &name: namesseen)
  {
    DNSName shorter(name);
    do {
      namestocheck.insert(shorter);
    } while(shorter.chopOff());
  }
  for(const auto &name: namestocheck)
  {
    proveOrDeny(nsec3s, name, nsec3salt, nsec3iters, proven, denied);
    proveOrDeny(nsec3s, g_wildcarddnsname+name, nsec3salt, nsec3iters, proven, denied);
  }

  if(names.count(qname))
  {
    cout<<"== qname found in names, investigating NSEC3s in case it's a wildcard"<<endl;
    // exit(EXIT_SUCCESS);
  }
  // cout<<"== qname not found in names, investigating denial"<<endl;
  if(proven.count(qname))
  {
    cout<<"qname found proven, NODATA response?"<<endl;
    exit(EXIT_SUCCESS);
  }
  DNSName shorter=qname;
  DNSName encloser;
  DNSName nextcloser;
  DNSName prev(qname);
  while(shorter.chopOff())
  {
    if(proven.count(shorter))
    {
      encloser=shorter;
      nextcloser=prev;
      cout<<"found closest encloser at "<<encloser.toString()<<endl;
      cout<<"next closer is "<<nextcloser.toString()<<endl;
      break;
    }
    prev=shorter;
  }
  if(encloser.countLabels() && nextcloser.countLabels())
  {
    if(denied.count(nextcloser))
    {
      cout<<"next closer ("<<nextcloser.toString()<<") is denied correctly"<<endl;
    }
    else
    {
      cout<<"next closer ("<<nextcloser.toString()<<") NOT denied"<<endl;
    }
    DNSName wcplusencloser=g_wildcarddnsname+encloser;
    if(denied.count(wcplusencloser))
    {
      cout<<"wildcard at encloser ("<<wcplusencloser.toString()<<") is denied correctly"<<endl;
    }
    else if(proven.count(wcplusencloser))
    {
      cout<<"wildcard at encloser ("<<wcplusencloser.toString()<<") is proven"<<endl;
    }
    else
    {
      cout<<"wildcard at encloser ("<<wcplusencloser.toString()<<") is NOT denied or proven"<<endl;
    }
  }
  exit(EXIT_SUCCESS);
}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
catch(PDNSException &e)
{
  cerr<<"Fatal: "<<e.reason<<endl;
}
