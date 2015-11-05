#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include "ednssubnet.hh"
#include "dnssecinfra.hh"
#include "recursor_cache.hh"
#include "base32.hh"
StatBag S;

class TCPResolver : public boost::noncopyable
{
public:
  TCPResolver(ComboAddress addr) : d_rsock(AF_INET, SOCK_STREAM)
  {
    d_rsock.connect(addr);
  }

  string query(const DNSName& qname, uint16_t qtype)
  {
    cerr<<"Q "<<qname<<"/"<<DNSRecordContent::NumberToType(qtype)<<endl;
    vector<uint8_t> packet;
    DNSPacketWriter pw(packet, qname, qtype);

    // recurse
    pw.getHeader()->rd=true;

    // we'll do the validation
    pw.getHeader()->cd=true;
    pw.getHeader()->ad=true;

    // we do require DNSSEC records to do that!
    pw.addOpt(2800, 0, EDNSOpts::DNSSECOK);
    pw.commit();

    uint16_t len;
    len = htons(packet.size());
    if(d_rsock.write((char *) &len, 2) != 2)
      throw PDNSException("tcp write failed");

    d_rsock.writen(string((char*)&*packet.begin(), (char*)&*packet.end()));
    
    if(d_rsock.read((char *) &len, 2) != 2)
      throw PDNSException("tcp read failed");

    len=ntohs(len);
    char *creply = new char[len];
    int n=0;
    int numread;
    while(n<len) {
      numread=d_rsock.read(creply+n, len-n);
      if(numread<0)
        throw PDNSException("tcp read failed");
      n+=numread;
    }

    string reply(creply, len);
    delete[] creply;

    return reply;
  }

  Socket d_rsock;
};


set<DSRecordContent> g_anchors;

vector<DNSKEYRecordContent> getKeys(Socket& sock, const DNSName& name, uint16_t tag, bool* trusted)
{
  *trusted=false;
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, name, QType::DNSKEY);
  pw.getHeader()->rd=1;
  pw.getHeader()->cd=1;
  pw.getHeader()->id=getpid();
  pw.addOpt(1800, 0, EDNSOpts::DNSSECOK);
  pw.commit();
  
  sock.send(string((char*)&*packet.begin(), (char*)&*packet.end()));
  string resp;
  sock.read(resp);
  MOADNSParser mdp(resp);
  vector<DNSKEYRecordContent> ret;
  shared_ptr<DNSKEYRecordContent> root;
  for(const auto& r : mdp.d_answers) {
    cout<<r.first.d_place-1<<"\t"<<r.first.d_name.toString()<<"\tIN\t"<<DNSRecordContent::NumberToType(r.first.d_type);
    cout<<"\t"<<r.first.d_content->getZoneRepresentation()<<endl;

    if(auto dk = getRR<DNSKEYRecordContent>(r.first)) {
      if(dk->getTag() == tag) {
	cout<<"Found key with tag "<<dk->getTag()<<endl;
	ret.push_back(*dk);
      }
      else {
	cout<<"Also got other key with tag "<<dk->getTag()<<" and DS ";
	auto ds=makeDSFromDNSKey(name, *dk, 2);
	cout<<ds.getZoneRepresentation()<<endl;
	if(g_anchors.count(ds)) {
	  cout<<"THIS IS THE ROOT"<<endl;
	  root = dk;
	}
      }
    }
    else if(auto rrsig = getRR<RRSIGRecordContent>(r.first)) {
      if(root) {
	cout<<"Had a signature on "<<r.first.d_name<<" "<<DNSRecordContent::NumberToType(r.first.d_type)<<" with tag "<<rrsig->d_tag<<endl;
	cout<<"Have a root dnskey with tag "<<rrsig->d_tag<<endl;
	auto engine = DNSCryptoKeyEngine::makeFromPublicKeyString(rrsig->d_algorithm, root->d_key);
	vector<shared_ptr<DNSRecordContent>> toSign;
	toSign.push_back(std::make_shared<DNSKEYRecordContent>(ret[0]));
	toSign.push_back(root);
	string msg = getMessageForRRSET(r.first.d_name, *rrsig, toSign);        
	*trusted=engine->verify(msg, rrsig->d_signature);
	cout<<"Result for signature in DNSKEY: "<<*trusted<<endl;
      }
    }
  }
  return ret;
}


unique_ptr<MOADNSParser> getMDP(const ComboAddress& dest, const DNSName& qname, uint16_t qtype)
{
  TCPResolver tr(dest);

  string resp=tr.query(qname, qtype);
  return unique_ptr<MOADNSParser>(new MOADNSParser(resp));

}


void lookup(const ComboAddress& dest, const DNSName& qname, uint16_t qtype)
{
  if(qname==DNSName(".") && qtype == QType::DS) {
    cerr<<"Hit root, should stop somehow ;-)"<<endl;
    exit(0);
  }
  Socket sock(dest.sin4.sin_family, SOCK_DGRAM);
  sock.connect(dest);
  vector<uint8_t> packet;

  DNSPacketWriter pw(packet, qname, qtype);
  pw.getHeader()->rd=1;
  pw.getHeader()->cd=1;
  pw.getHeader()->id=getpid();
  pw.addOpt(1800, 0, EDNSOpts::DNSSECOK);
  pw.commit();

  sock.send(string((char*)&*packet.begin(), (char*)&*packet.end()));
  string resp;
  sock.read(resp);
  MOADNSParser mdp(resp);

  struct ContentPair {
    vector<DNSRecord> content;
    vector<shared_ptr<RRSIGRecordContent>> signatures;
  };

  map<pair<DNSName,uint16_t>, ContentPair > records;

  for(const auto& r : mdp.d_answers) {
    cout<<r.first.d_place-1<<"\t"<<r.first.d_name.toString()<<"\tIN\t"<<DNSRecordContent::NumberToType(r.first.d_type);
    cout<<"\t"<<r.first.d_content->getZoneRepresentation()<<endl;

    if(auto rrsig = getRR<RRSIGRecordContent>(r.first)) {
      records[make_pair(r.first.d_name, rrsig->d_type)].signatures.push_back(rrsig);
    }
    else if(auto opt = getRR<OPTRecordContent>(r.first)) {
      continue;
    }

    else
      records[make_pair(r.first.d_name, r.first.d_type)].content.push_back(r.first);

  }
  cout<<"Had "<<records.size()<<" RRSETs"<<endl;
  for(auto& rrset : records) {
    vector<shared_ptr<DNSRecordContent> > toSign;
    for(const auto& c : rrset.second.content) 
      toSign.push_back(c.d_content);

    for(auto& sign : rrset.second.signatures) {
      cout<<"Seeing if we can retrieve DNSKEY for "<<sign->d_signer<<" with tag "<<sign->d_tag<<endl;
      bool trusted=false;
      auto keys=getKeys(sock, sign->d_signer, sign->d_tag, &trusted);
      cout<<"Got "<<keys.size()<<" keys"<<endl;
      for(const auto& key : keys) {
	auto engine = DNSCryptoKeyEngine::makeFromPublicKeyString(key.d_algorithm, key.d_key);
	string msg = getMessageForRRSET(rrset.first.first, *sign, toSign);        
	cout<<"Result for signature on "<<rrset.first.first<<" "<<DNSRecordContent::NumberToType(rrset.first.second)<<": "<<engine->verify(msg, sign->d_signature)<<endl;

	if(trusted) {
	  cerr<<"This key is trusted ultimately"<<endl;
	  return;
	}
	else {

	  cerr<<"Should go looking for DS on DNSKEY "<<sign->d_signer<<endl;
	  lookup(dest, sign->d_signer, QType::DS);
	}
      }
    }
  }
}

// 4033 5
// FIXME: namespace this
enum vState { Indeterminate, Bogus, Insecure, Secure };
const char *vStates[]={"Indeterminate", "Bogus", "Insecure", "Secure"};

// NSEC(3) results
// FIXME: namespace this
enum dState { NODATA, NXDOMAIN, ENT, INSECURE };
const char *dStates[]={"nodata", "nxdomain", "empty non-terminal", "insecure (no-DS proof)"};


typedef std::multimap<uint16_t, DNSKEYRecordContent> keymap_t;


string nsec3Hash(const DNSName &qname, const NSEC3RecordContent& nrc)
{
  NSEC3PARAMRecordContent ns3pr;
  ns3pr.d_iterations = nrc.d_iterations;
  ns3pr.d_salt = nrc.d_salt;
  return toBase32Hex(hashQNameWithSalt(ns3pr, qname));
}




typedef map<pair<DNSName, uint16_t>, set<shared_ptr<DNSRecordContent> > > rrsetmap_t;

typedef pair<DNSName, uint16_t> NT; // Name/Type pair
typedef std::multimap<NT, shared_ptr<DNSRecordContent> > recmap_t;
typedef std::multimap<NT, RRSIGRecordContent> sigmap_t;
typedef std::multimap<NT, shared_ptr<DNSRecordContent> > nsecmap_t;

typedef pair<DNSName, uint16_t> ZT; //Zonename/keyTag pair
// recmap_t g_recs; // fetched recs for full chain validation
// keymap_t g_keys; // fetched keys
// keymap_t g_vkeys; // validated keys

// FIXME: needs a zone argument, to avoid things like 6840 4.1
dState getDenial(rrsetmap_t &validrrsets, DNSName qname, uint16_t qtype)
{
  std::multimap<DNSName, NSEC3RecordContent> nsec3s;

  for(rrsetmap_t::const_iterator i=validrrsets.begin(); i!=validrrsets.end(); ++i)
  {
    // FIXME also support NSEC
    if(i->first.second != QType::NSEC3) continue;
    
    for(set<shared_ptr<DNSRecordContent> >::const_iterator j=i->second.begin(); j!=i->second.end(); ++j) {
      NSEC3RecordContent ns3r = dynamic_cast<NSEC3RecordContent&> (**j);
      // nsec3.insert(new nsec3()
      // cerr<<toBase32Hex(r.d_nexthash)<<endl;
      nsec3s.insert(make_pair(i->first.first, ns3r));
    }
  }
  cerr<<"got "<<nsec3s.size()<<" NSEC3s"<<endl;
  for(auto i=nsec3s.begin(); i != nsec3s.end(); ++i) {
    vector<string> parts = i->first.getRawLabels();

      string base=toLower(parts[0]);
      string next=toLower(toBase32Hex(i->second.d_nexthash));
      string hashed = nsec3Hash(qname, i->second);
      cerr<<base<<" .. ? "<<hashed<<" ("<<qname<<") ? .. "<<next<<endl;
      if(base==hashed) {
        // positive name proof, need to check type
        cerr<<"positive name proof, checking type bitmap"<<endl;
        cerr<<"d_set.count("<<qtype<<"): "<<i->second.d_set.count(qtype)<<endl;
        if(qtype == QType::DS && i->second.d_set.count(qtype) == 0) return INSECURE; // FIXME need to require 'NS in bitmap' here, otherwise no delegation! (but first, make sure this is reliable - does not work that way for direct auth queries)
      } else if ((hashed > base && hashed < next) ||
                (next < base && (hashed < next || hashed > base))) {
        bool optout=(1 & i->second.d_flags);
        cerr<<"negative name proof, optout = "<<optout<<endl;
        if(qtype == QType::DS && optout) return INSECURE;
      }
  }
  dState ret;
  return ret;
}
/*

string dotEscape(string name)
{
  return "\"" + boost::replace_all_copy(name, "\"", "\\\"") + "\"";
}

string dotName(string type, string name, string tag)
{
  if(tag == "")
    return type+" "+name;
  else
    return type+" "+name+"/"+tag;
}
void dotNode(string type, string name, string tag, string content)
{
  cout<<"    "
      <<dotEscape(dotName(type, name, tag))
      <<" [ label="<<dotEscape(dotName(type, name, tag)+"\\n"+content)<<" ];"<<endl;
}

void dotEdge(DNSName zone, string type1, DNSName name1, DNSName tag1, string type2, DNSName name2, DNSName tag2, string color="")
{
  cout<<"    ";
  if(zone != DNSName(".")) cout<<"subgraph "<<dotEscape("cluster "+zone.toString())<<" { ";
  cout<<dotEscape(dotName(type1, name1, tag1))
      <<" -> "
      <<dotEscape(dotName(type2, name2, tag2));
  if(color != "") cout<<" [ color=\""<<color<<"\" ]; ";
  else cout<<"; ";
  if(zone != DNSName(".")) cout<<"label = "<<dotEscape("zone: "+zone.toString())<<";"<<"}";
  cout<<endl;
}
*/

void validateWithKeySet(rrsetmap_t& rrsets, rrsetmap_t& rrsigs, rrsetmap_t& validated, keymap_t& keys)
{
  for(rrsetmap_t::const_iterator i=rrsets.begin(); i!=rrsets.end(); i++)
  {
    cerr<<"validating "<<(i->first.first)<<"/"<<DNSRecordContent::NumberToType(i->first.second)<<endl;
    pair<rrsetmap_t::const_iterator, rrsetmap_t::const_iterator> r = rrsigs.equal_range(make_pair(i->first.first, i->first.second));
    for(rrsetmap_t::const_iterator j=r.first; j!=r.second; j++) {
      for(set<shared_ptr<DNSRecordContent> >::const_iterator k=j->second.begin(); k!=j->second.end(); k++) {
        vector<shared_ptr<DNSRecordContent> > toSign;
        set<shared_ptr<DNSRecordContent> > rrs = rrsets[make_pair(j->first.first, j->first.second)];
        toSign.assign(rrs.begin(), rrs.end());

        const RRSIGRecordContent rrc=dynamic_cast<const RRSIGRecordContent&> (*(*k));

        if(!keys.count(rrc.d_tag)) continue;

        string msg=getMessageForRRSET(j->first.first, rrc, toSign);
        pair<keymap_t::const_iterator, keymap_t::const_iterator> r = keys.equal_range(rrc.d_tag); // FIXME: also take algorithm into account? right now we wrongly validate unknownalgorithm.bad-dnssec.wb.sidnlabs.nl
        for(keymap_t::const_iterator l=r.first; l!=r.second; l++) {
          bool isValid = DNSCryptoKeyEngine::makeFromPublicKeyString(l->second.d_algorithm, l->second.d_key)->verify(msg, rrc.d_signature);
          if(isValid) {
            validated[make_pair(j->first.first, j->first.second)] = rrs;
            cerr<<"valid"<<endl;
            cerr<<"! validated "<<j->first.first<<"/"<<DNSRecordContent::NumberToType(rrc.d_type)<<endl;
          }
          if(rrc.d_type != QType::DNSKEY) {
	    /*              dotEdge(rrc.d_signer,
                    "DNSKEY", rrc.d_signer, lexical_cast<string>(rrc.d_tag),
                    DNSRecordContent::NumberToType(rrc.d_type), j->first.first, "", isValid ? "green" : "red");
	    */
          }
          // FIXME: break out enough levels
        }
      }
    }
  }
}

// returns vState
// should return vState, zone cut and validated keyset
// i.e. www.7bits.nl -> insecure/7bits.nl/[]
//      www.powerdnssec.org -> secure/powerdnssec.org/[keys]
//      www.dnssec-failed.org -> bogus/dnssec-failed.org/[]

char *rootDS;

vState getKeysFor(TCPResolver& tr, const DNSName& zone, keymap_t &keyset)
{
  vector<string> labels = zone.getRawLabels();
  vState state;

  state = Indeterminate;

  DNSName qname;
  typedef std::multimap<uint16_t, DSRecordContent> dsmap_t;
  dsmap_t dsmap;
  keymap_t keymap;
  recmap_t recs;

  state = Secure;
  while(zone.isPartOf(qname))
  {
    if(qname.isRoot())
    {
      DSRecordContent rootanchor=dynamic_cast<DSRecordContent&> (*(DNSRecordContent::mastermake(QType::DS, 1, rootDS)));
      dsmap.clear();
      dsmap.insert(make_pair(rootanchor.d_tag, rootanchor));
    }
  
    recs.clear();
    vector<RRSIGRecordContent> sigs;
    vector<shared_ptr<DNSRecordContent> > toSign;
    vector<uint16_t> toSignTags;

    keymap_t tkeymap; // tentative keys
    keymap.clear();
    
    // start of this iteration
    // we can trust that dsmap has valid DS records for qname

    cerr<<"got DS for ["<<qname<<"], grabbing DNSKEYs"<<endl;
    MOADNSParser mdp(tr.query(qname, (uint16_t)QType::DNSKEY));

    for(auto i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {
      if(i->first.d_name != qname)
        continue;

      if(i->first.d_type == QType::RRSIG)
      {
        RRSIGRecordContent rrc=dynamic_cast<RRSIGRecordContent&> (*(i->first.d_content));
        if(rrc.d_type != QType::DNSKEY)
          continue;
        sigs.push_back(rrc);
      }
      else if(i->first.d_type == QType::DNSKEY)
      {
        DNSKEYRecordContent drc=dynamic_cast<DNSKEYRecordContent&> (*(i->first.d_content));
        tkeymap.insert(make_pair(drc.getTag(), drc));
	//        dotNode("DNSKEY", qname, lexical_cast<string>(drc.getTag()), (boost::format("tag=%d, algo=%d") % drc.getTag() % static_cast<int>(drc.d_algorithm)).str());

        toSign.push_back(i->first.d_content);
        toSignTags.push_back(drc.getTag());
      }
    }
    cerr<<"got "<<tkeymap.size()<<" keys and "<<sigs.size()<<" sigs"<<endl;

    for(dsmap_t::const_iterator i=dsmap.begin(); i!=dsmap.end(); i++)
    {
      DSRecordContent dsrc=i->second;
      cerr<<"got DS with tag "<<dsrc.d_tag<<"/"<<i->first<<", got "<<tkeymap.count(i->first)<<" DNSKEYs for tag"<<endl;
      pair<keymap_t::const_iterator, keymap_t::const_iterator> r = tkeymap.equal_range(i->first);
      for(keymap_t::const_iterator j=r.first; j!=r.second; j++)
      {
        DNSKEYRecordContent drc=j->second;
        DSRecordContent dsrc2=makeDSFromDNSKey(qname, drc, dsrc.d_digesttype);
        bool isValid = dsrc == dsrc2;
        if(isValid) {
          cerr<<"got valid DNSKEY"<<endl;
          keymap.insert(make_pair(drc.getTag(), drc));
	  //          dotNode("DS", qname, "" /*lexical_cast<string>(dsrc.d_tag)*/, (boost::format("tag=%d, digest algo=%d, algo=%d") % dsrc.d_tag % static_cast<int>(dsrc.d_digesttype) % static_cast<int>(dsrc.d_algorithm)).str());
        }
        // cout<<"    subgraph "<<dotEscape("cluster "+qname)<<" { "<<dotEscape("DS "+qname)<<" -> "<<dotEscape("DNSKEY "+qname)<<" [ label = \""<<dsrc.d_tag<<"/"<<static_cast<int>(dsrc.d_digesttype)<<"\" ]; label = \"zone: "<<qname<<"\"; }"<<endl;
	//        dotEdge("", "DS", qname, "" /*lexical_cast<string>(dsrc.d_tag)*/, "DNSKEY", qname, lexical_cast<string>(drc.getTag()), isValid ? "green" : "red");
        // dotNode("DNSKEY", qname, (boost::format("tag=%d, algo=%d") % drc.getTag() % static_cast<int>(drc.d_algorithm)).str());
      }
    }

    cerr<<"got "<<keymap.size()<<"/"<<tkeymap.size()<<" valid/tentative keys"<<endl;
    // these counts could be off if we somehow ended up with 
    // duplicate keys. Should switch to a type that prevents that.
    if(keymap.size() < tkeymap.size())
    {
      // this should mean that we have one or more DS-validated DNSKEYs
      // but not a fully validated DNSKEY set, yet
      // one of these valid DNSKEYs should be able to validate the
      // whole set
      for(auto i=sigs.begin(); i!=sigs.end(); i++)
      {
        cerr<<"got sig for keytag "<<i->d_tag<<" matching "<<tkeymap.count(i->d_tag)<<" keys of which "<<keymap.count(i->d_tag)<<" valid"<<endl;
        string msg=getMessageForRRSET(qname, *i, toSign);
        pair<keymap_t::const_iterator, keymap_t::const_iterator> r = keymap.equal_range(i->d_tag);
        for(keymap_t::const_iterator j=r.first; j!=r.second; j++) {
          cerr<<"validating"<<endl;
          bool isValid = DNSCryptoKeyEngine::makeFromPublicKeyString(j->second.d_algorithm, j->second.d_key)->verify(msg, i->d_signature);
	  //          for(uint16_t tag : toSignTags) {
	    //            dotEdge(qname,
	    //      "DNSKEY", qname, lexical_cast<string>(i->d_tag),
	    //      "DNSKEY", qname, lexical_cast<string>(tag), isValid ? "green" : "red");
	  //          }

          if(isValid)
          {
            cerr<<"validation succeeded - whole DNSKEY set is valid"<<endl;
            // cout<<"    "<<dotEscape("DNSKEY "+stripDot(i->d_signer))<<" -> "<<dotEscape("DNSKEY "+qname)<<";"<<endl;
            keymap=tkeymap;
            break;
          }
        }
        if(!keymap.size()) cerr<<"did not manage to validate DNSKEY set based on DS-validated KSK, only passing KSK on"<<endl;
      }
    }

    if(!keymap.size())
    {
      cerr<<"ended up with zero valid DNSKEYs, going Bogus"<<endl;
      state=Bogus;
      break;
    }
    cerr<<"situation: we have one or more valid DNSKEYs for ["<<qname<<"] (want ["<<zone<<"])"<<endl;
    if(qname == zone) {
      cerr<<"requested keyset found! returning Secure"<<endl;
      keyset.insert(keymap.begin(), keymap.end());
      return Secure;
    }
    cerr<<"walking downwards to find DS"<<endl;
    DNSName keyqname=qname;
    do {
      qname=DNSName(labels.back())+qname;
      labels.pop_back();
      cerr<<"next name ["<<qname<<"], trying to get DS"<<endl;

      recs.clear();
      sigs.clear();
      dsmap_t tdsmap; // tentative DSes
      dsmap.clear();
      toSign.clear();
      toSignTags.clear();

      MOADNSParser mdp(tr.query(qname, QType::DS));

      rrsetmap_t rrsets;
      rrsetmap_t rrsigs;

      for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {
        cerr<<"res "<<i->first.d_name<<"/"<<i->first.d_type<<endl;
        if(i->first.d_type == QType::OPT) continue;

        if(i->first.d_type == QType::RRSIG) {
          RRSIGRecordContent rrc = dynamic_cast<RRSIGRecordContent&> (*(i->first.d_content));
          rrsigs[make_pair(i->first.d_name,rrc.d_type)].insert(i->first.d_content);
        }
        else {
          rrsets[make_pair(i->first.d_name,i->first.d_type)].insert(i->first.d_content);
        }
      }

      rrsetmap_t validrrsets;
      validateWithKeySet(rrsets, rrsigs, validrrsets, keymap);

      cerr<<"got "<<rrsets.count(make_pair(qname,QType::DS))<<" DS of which "<<validrrsets.count(make_pair(qname,QType::DS))<<" valid "<<endl;

      auto r = validrrsets.equal_range(make_pair(qname, QType::DS));
      for(rrsetmap_t::const_iterator i=r.first; i!=r.second; i++) {
        for(set<shared_ptr<DNSRecordContent> >::const_iterator j=i->second.begin(); j!=i->second.end(); j++)
        {
          const DSRecordContent dsrc=dynamic_cast<const DSRecordContent&> (**j);
          dsmap.insert(make_pair(dsrc.d_tag, dsrc));
          // dotEdge(keyqname,
          //         "DNSKEY", keyqname, ,
          //         "DS", qname, lexical_cast<string>(dsrc.d_tag));
          // cout<<"    "<<dotEscape("DNSKEY "+keyqname)<<" -> "<<dotEscape("DS "+qname)<<";"<<endl;
        }
      }
      if(!dsmap.size()) {
        cerr<<"no DS at this level, checking for denials"<<endl;
        dState dres = getDenial(validrrsets, qname, QType::DS);
        if(dres == INSECURE) return Insecure;
      }
    } while(!dsmap.size() && labels.size());

    // break;
  }

  return state;
}




int main(int argc, char** argv)
try
{
  reportAllTypes();
  g_anchors.insert(DSRecordContent("19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5"));
  if(argc < 4) {
    cerr<<"Syntax: sdig IP-address port question question-type\n";
    exit(EXIT_FAILURE);
  }
  ComboAddress dest(argv[1] + (*argv[1]=='@'), atoi(argv[2]));
  DNSName qname(argv[3]);
  uint16_t qtype=DNSRecordContent::TypeToNumber(argv[4]);
  TCPResolver tr(dest);

  cout<<"digraph oneshot {"<<endl;

  auto mdp=getMDP(dest, qname, qtype);

  rrsetmap_t rrsets;
  rrsetmap_t rrsigs;

  for(auto i = mdp->d_answers.begin(); i != mdp->d_answers.end(); ++i) {
    cerr<<"res "<<i->first.d_name<<"/"<<i->first.d_type<<endl;
    if(i->first.d_type == QType::OPT) continue;

    if(i->first.d_type == QType::RRSIG) {
      RRSIGRecordContent rrc = dynamic_cast<RRSIGRecordContent&> (*(i->first.d_content));
      rrsigs[make_pair(i->first.d_name,rrc.d_type)].insert(i->first.d_content);
    }
    else {
      rrsets[make_pair(i->first.d_name,i->first.d_type)].insert(i->first.d_content);
    }
  }

  cerr<<"got "<<rrsigs.size()<<" sigs for "<<rrsets.size()<<" sets"<<endl;

  pair<rrsetmap_t::const_iterator, rrsetmap_t::const_iterator> r = rrsigs.equal_range(make_pair(qname, qtype));
  cerr<<"got "<<rrsigs.count(make_pair(qname, qtype))<<" applicable sigs"<<endl;

  keymap_t keys;
  rrsetmap_t validrrsets;

  if(rrsigs.size()) {
    for(rrsetmap_t::const_iterator i=rrsigs.begin(); i!=rrsigs.end(); i++) {
      cerr<<"A"<<endl;
      for(set<shared_ptr<DNSRecordContent> >::const_iterator j=i->second.begin(); j!=i->second.end(); j++)
      {
        cerr<<"B"<<endl;
        const RRSIGRecordContent rrc=dynamic_cast<const RRSIGRecordContent&> (*(*j));
        cerr<<"got rrsig "<<rrc.d_signer<<"/"<<rrc.d_tag<<endl;
        vState state = getKeysFor(tr, rrc.d_signer, keys);
        cerr<<"! state = "<<vStates[state]<<", now have "<<keys.size()<<" keys at "<<qname<<endl;
        // dsmap.insert(make_pair(dsrc.d_tag, dsrc));
      }
    }
    validateWithKeySet(rrsets, rrsigs, validrrsets, keys);
  }
  else {
    cerr<<"no sigs, hoping for Insecure"<<endl;
    vState state = getKeysFor(tr, qname, keys);
    cerr<<"! state = "<<vStates[state]<<", now have "<<keys.size()<<" keys at "<<qname<<endl;
  }
  cerr<<"! validated "<<validrrsets.size()<<" RRsets out of "<<rrsets.size()<<endl;

  cerr<<"% validated RRs:"<<endl;
  for(rrsetmap_t::const_iterator i=validrrsets.begin(); i!=validrrsets.end(); i++) {
    cerr<<"% "<<i->first.first<<"/"<<DNSRecordContent::NumberToType(i->first.second)<<endl;
    for(set<shared_ptr<DNSRecordContent> >::const_iterator j=i->second.begin(); j!=i->second.end(); j++) {
      cerr<<"% > "<<(*j)->getZoneRepresentation()<<endl;
    }
  }

  cout<<"}"<<endl;
  exit(0);



}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
