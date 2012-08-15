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

string nsec3Hash(const string &qname, const string &salt, unsigned int iters)
{
  return toLower(toBase32Hex(hashQNameWithSalt(iters, salt, qname)));
}

void proveOrDeny(const nsec3set &nsec3s, const string &qname, const string &salt, unsigned int iters, set<string> &proven, set<string> &denied)
{
  string hashed = nsec3Hash(qname, salt, iters);

  // cerr<<"hashed: "<<hashed<<endl;
  for(nsec3set::const_iterator pos=nsec3s.begin(); pos != nsec3s.end(); ++pos) {
    string base=(*pos).first;
    string next=(*pos).second;

    if(hashed == base)
    {
      proven.insert(qname);
      cout<<qname<<" ("<<hashed<<") proven by base of "<<base<<".."<<next<<endl;
    }
    if(hashed == next)
    {
      proven.insert(qname);
      cout<<qname<<" ("<<hashed<<") proven by next of "<<base<<".."<<next<<endl;
    }
    if((hashed > base && hashed < next) ||
       (next < base && (hashed < next || hashed > base)))
    {
      denied.insert(qname);
      cout<<qname<<" ("<<hashed<<") denied by "<<base<<".."<<next<<endl;
    }
    if (base == next && base != hashed)
    {
      denied.insert(qname);
      cout<<qname<<" ("<<hashed<<") denied by "<<base<<".."<<next<<endl;
    }
  }
}

int main(int argc, char** argv)
try
{
  bool recurse=false;

  reportAllTypes();

  if(argc < 5) {
    cerr<<"Syntax: nsec3dig IP-address port question question-type [recurse]\n";
    exit(EXIT_FAILURE);
  }

  // FIXME: turn recurse and dnssec into proper flags or something
  if(argc > 5 && strcmp(argv[5], "recurse")==0)
  {
    recurse=true;
  }

  vector<uint8_t> packet;
  string qname=argv[3];
  DNSPacketWriter pw(packet, qname, DNSRecordContent::TypeToNumber(argv[4]));

  if(recurse)
  {
    pw.getHeader()->rd=true;
  }

  pw.addOpt(2800, 0, EDNSOpts::DNSSECOK);
  pw.commit();

  Socket sock(InterNetwork, Datagram);
  ComboAddress dest(argv[1] + (*argv[1]=='@'), atoi(argv[2]));
  sock.sendTo(string((char*)&*packet.begin(), (char*)&*packet.end()), dest);
  
  string reply;
  sock.recvFrom(reply, dest);

  MOADNSParser mdp(reply);
  cout<<"Reply to question for qname='"<<mdp.d_qname<<"', qtype="<<DNSRecordContent::NumberToType(mdp.d_qtype)<<endl;
  cout<<"Rcode: "<<mdp.d_header.rcode<<", RD: "<<mdp.d_header.rd<<", QR: "<<mdp.d_header.qr;
  cout<<", TC: "<<mdp.d_header.tc<<", AA: "<<mdp.d_header.aa<<", opcode: "<<mdp.d_header.opcode<<endl;

  set<string> names;
  nsec3set nsec3s;
  string nsec3salt;
  int nsec3iters;
  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {     
    if(i->first.d_type == QType::NSEC3)
    {
      // cerr<<"got nsec3 ["<<i->first.d_label<<"]"<<endl;
      // cerr<<i->first.d_content->getZoneRepresentation()<<endl;
      NSEC3RecordContent r = dynamic_cast<NSEC3RecordContent&> (*(i->first.d_content));
      // nsec3.insert(new nsec3()
      // cerr<<toBase32Hex(r.d_nexthash)<<endl;
      vector<string> parts;
      boost::split(parts, i->first.d_label, boost::is_any_of("."));
      nsec3s.insert(make_pair(toLower(parts[0]), toLower(toBase32Hex(r.d_nexthash))));
      nsec3salt = r.d_salt;
      nsec3iters = r.d_iterations;
    }
    else
    {
      names.insert(i->first.d_label);
    }

    cout<<i->first.d_place-1<<"\t"<<i->first.d_label<<"\tIN\t"<<DNSRecordContent::NumberToType(i->first.d_type);
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
  set<string> proven;
  set<string> denied;
  string shorter(qname);
  do {
    proveOrDeny(nsec3s, shorter, nsec3salt, nsec3iters, proven, denied);
    proveOrDeny(nsec3s, "*."+shorter, nsec3salt, nsec3iters, proven, denied);
  } while(chopOff(shorter));

  if(names.count(qname+"."))
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
  shorter=qname;
  string encloser;
  string nextcloser;
  string prev(qname);
  while(chopOff(shorter))
  {
    if(proven.count(shorter))
    {
      encloser=shorter;
      nextcloser=prev;
      cout<<"found closest encloser at "<<encloser<<endl;
      cout<<"next closer is "<<nextcloser<<endl;
      break;
    }
    prev=shorter;
  }
  if(encloser.size() && nextcloser.size())
  {
    if(denied.count(nextcloser))
    {
      cout<<"next closer ("<<nextcloser<<") is denied correctly"<<endl;
    }
    else
    {
      cout<<"next closer ("<<nextcloser<<") NOT denied"<<endl;
    }
    if(denied.count("*."+encloser))
    {
      cout<<"wildcard at encloser (*."<<encloser<<") is denied correctly"<<endl;
    }
    else if(proven.count("*."+encloser))
    {
      cout<<"wildcard at encloser (*."<<encloser<<") is proven"<<endl;
    }
    else
    {
      cout<<"wildcard at encloser (*."<<encloser<<") is NOT denied or proven"<<endl;
    }
  }
  exit(EXIT_SUCCESS);
}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
