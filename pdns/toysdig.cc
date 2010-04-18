#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include "iputils.hh"
#include <netinet/sctp.h>
#include <boost/foreach.hpp>
#include <polarssl/rsa.h>
#include <polarssl/base64.h>
#include <polarssl/sha1.h>
#include "dnssecinfra.hh"
#include "base32.hh"

StatBag S;

MOADNSParser* askQuestion(DNSPacketWriter&, vector<uint8_t>& packet, const char* remote, uint16_t port=53) 
{
  int sock=socket(AF_INET, SOCK_DGRAM, 0);
  
  if(sock < 0)
    unixDie("Creating SCTP socket");
  
  ComboAddress dest(remote + (*remote=='@'), port);
  struct msghdr msg;
  struct iovec iomsg;
  
  msg.msg_name=&dest;
  msg.msg_namelen=dest.getSocklen();
  msg.msg_iov=&iomsg;
  iomsg.iov_base=&*packet.begin();
  iomsg.iov_len=packet.size();
  msg.msg_iovlen=1;
  msg.msg_control=0;
  msg.msg_controllen=0;
  msg.msg_flags=0; // just to be sure
  
  sendmsg(sock, &msg, 0); 
  
  char replybuf[4096];
  socklen_t destlen=dest.getSocklen();
  int len=recvfrom(sock, replybuf, sizeof(replybuf), 0, (struct sockaddr*)&dest, &destlen);
  if(len < 0)
    unixDie("recvfrom on sctp");
  
  string reply(replybuf, len);
  
  return new MOADNSParser(reply);
}

void getKeys(const std::string& qname, uint16_t tag);

void doVerifySignature(const std::string& qname,  map<string, vector<shared_ptr<DNSKEYRecordContent > > >& dkrcs, pair<vector<shared_ptr<DNSRecordContent> >, vector<shared_ptr<RRSIGRecordContent> > >& records)
{
  rsa_context rsa;

  BOOST_FOREACH(shared_ptr<RRSIGRecordContent>& rrc, records.second) {
    cerr<<"\nVerifying "<<qname<<"|"<<DNSRecordContent::NumberToType(rrc->d_type)<<"\n";

    cerr<<"Signer is: "<<rrc->d_signer<<" for which we have "<<dkrcs[rrc->d_signer].size()<<" DNSKEYs, want the one with";
    cerr<<" tag: "<<rrc->d_tag<<endl;
  

    getKeys(rrc->d_signer, rrc->d_tag);

    if(dkrcs[rrc->d_signer].empty())  {
      cerr<<"\tNo keys!\n";
      return;
    }
    
    vector<shared_ptr<DNSRecordContent> >& signRecords= records.first;
  
    string hash=getSHA1HashForRRSET(qname, *rrc.get(), signRecords);
    int ret;
    int success=0;
    BOOST_FOREACH(shared_ptr<DNSKEYRecordContent> dkrc, dkrcs[rrc->d_signer]) {
      if(dkrc->getTag() != rrc->d_tag) {
	cerr<<"Skipping key with wrong tag "<<dkrc->getTag()<< " != needed "<<rrc->d_tag<<endl;
	continue;
      }
      makeRSAPublicKeyFromDNS(&rsa, *dkrc);
  
      if((ret=rsa_pkcs1_verify(&rsa, RSA_PUBLIC, SIG_RSA_SHA1, 20, (unsigned char*)hash.c_str(), (unsigned char*)rrc->d_signature.c_str() ) ) != 0) {
	fprintf(stderr, "Verification with tag %d failed with error %d\n", dkrc->getTag(), ret);
      }
      else {
	fprintf(stderr, "DNSSEC Record verified Ok with tag %d!\n", dkrc->getTag());
	success++;
	break;
      }
    }
    if(success)
      cerr<<"\t at least one verification was succesful!\n";
  }
}

typedef map<string, vector<shared_ptr<DNSKEYRecordContent> > > dkrc_t;
dkrc_t dkrc;

void getKeys(const std::string& qname, uint16_t tag)
{
  BOOST_FOREACH(shared_ptr<DNSKEYRecordContent>& drc, dkrc[qname]) {
    if(drc->getTag() == tag) 
      return;
  }

  vector<uint8_t> packet;
  
  DNSPacketWriter pw(packet, qname, QType::DNSKEY);

  pw.getHeader()->id=1234;
  pw.getHeader()->rd=1;

  pw.addOpt(4000, 0, EDNSOpts::DNSSECOK); // int udpsize, int extRCode, int Z 
  pw.commit();

  MOADNSParser* mdp=askQuestion(pw, packet, "199.249.112.1", 53);
  if(mdp->d_header.tc) {
    cerr<<"Truncated!\n";
  }
  for(MOADNSParser::answers_t::const_iterator i=mdp->d_answers.begin(); i!=mdp->d_answers.end(); ++i) {          
    if(i->first.d_type==QType::DNSKEY) {
      shared_ptr<DNSKEYRecordContent> dkrcptr=dynamic_pointer_cast<DNSKEYRecordContent>(i->first.d_content);
      dkrc[i->first.d_label].push_back(dkrcptr);
      cerr<<"Added DNSKEY for '"<<qname<<"': tag = "<<dkrcptr->getTag()<<", key length = "<<dkrcptr->getModulus().length()*8<<", SEP = "<< dkrcptr->d_flags%2 <<endl;
    }
  }
}

int main(int argc, char** argv)
try
{
  reportAllTypes();

  if(argc < 4) {
    cerr<<"Syntax: toysdig question question-type IP-address [port]\n";
    exit(EXIT_FAILURE);
  }

  vector<uint8_t> packet;
  
  DNSPacketWriter pw(packet, argv[1], DNSRecordContent::TypeToNumber(argv[2]));

  pw.getHeader()->id=1234;
  pw.getHeader()->rd=0;

  pw.addOpt(4000, 0, EDNSOpts::DNSSECOK); // int udpsize, int extRCode, int Z 
  pw.commit();

  MOADNSParser* mdp=askQuestion(pw, packet, argv[3], argc>4 ? atoi(argv[4]) : 53);
  if(mdp->d_header.tc) {
    cerr<<"Truncated!\n";
  }
  
  typedef map< pair<string, uint16_t>, 
    pair<vector<shared_ptr<DNSRecordContent> >, vector<shared_ptr<RRSIGRecordContent> > 
    > > grouped_t;
  grouped_t grouped;
  
  string salt;
  int iterations;
  for(MOADNSParser::answers_t::const_iterator i=mdp->d_answers.begin(); i!=mdp->d_answers.end(); ++i) {          
    cout<<i->first.d_place-1<<"\t"<<i->first.d_label<<"\tIN\t"<<DNSRecordContent::NumberToType(i->first.d_type);
    cout<<"\t"<<i->first.d_ttl<<"\t"<< i->first.d_content->getZoneRepresentation()<<"\n";

    if(i->first.d_type==QType::DNSKEY) {
      dkrc[i->first.d_label].push_back(dynamic_pointer_cast<DNSKEYRecordContent>(i->first.d_content));
    }

    if(i->first.d_type==QType::NSEC3) {
      salt=dynamic_pointer_cast<NSEC3RecordContent>(i->first.d_content)->d_salt;
      iterations=dynamic_pointer_cast<NSEC3RecordContent>(i->first.d_content)->d_iterations;
    }

    
    if(i->first.d_type!=QType::RRSIG) 
      grouped[make_pair(i->first.d_label, i->first.d_type)].first.push_back(i->first.d_content);
    else {
      shared_ptr<RRSIGRecordContent> rrc=dynamic_pointer_cast<RRSIGRecordContent>(i->first.d_content);
      grouped[make_pair(i->first.d_label, rrc->d_type)].second.push_back(rrc);
      cerr<<"Algorithm = "<<(int)rrc->d_algorithm<<endl;
    }

  }

  if(!salt.empty()) {
    cerr<<"We have a salt ("<<makeHexDump(salt)<<"), the NSEC3 of our query name ("<<argv[1]<<"): "<<toBase32Hex(hashQNameWithSalt(iterations, salt, argv[1]))<<endl;
  }

  cerr<<"Now have different names of "<<dkrc.size()<<" dnskeys!"<<endl;

  BOOST_FOREACH(dkrc_t::value_type& value, dkrc) {
    BOOST_FOREACH(shared_ptr<DNSKEYRecordContent>& content, value.second) {
      DSRecordContent dsrc = makeDSFromDNSKey(value.first, *content.get());
      cerr<<"ds: "<<value.first<<" IN DS "<<dsrc.getZoneRepresentation()<<endl;
      dsrc = makeDSFromDNSKey(value.first, *content.get(),2);
      cerr<<"ds: "<<value.first<<" IN DS "<<dsrc.getZoneRepresentation()<<endl;

    }
  }

  cerr<<"\n";
  BOOST_FOREACH(grouped_t::value_type& value, grouped) {
    if(value.second.first.empty() && !value.second.second.empty()) 
      cerr<<"Have a loose signature for"<<value.first.first<<"|"<<DNSRecordContent::NumberToType(value.first.second)<<endl;
    else if(!value.second.first.empty() && value.second.second.empty()) 
      cerr<<"Have unsigned content: "<<value.first.first<<"|"<<DNSRecordContent::NumberToType(value.first.second)<<endl;
    else if(!value.second.first.empty() && !value.second.second.empty()) {
      cerr<<"Have signed content: "<<value.first.first<<"|"<<DNSRecordContent::NumberToType(value.first.second);
      cerr<<" ("<<value.second.first.size()<<" recs, "<<value.second.second.size()<<" signatures)"<<endl;
      doVerifySignature(value.first.first, dkrc, value.second);
    }
    else
      cerr<<"Have empty content?? "<<value.first.first<<"|"<<DNSRecordContent::NumberToType(value.first.second)<<endl;
  }


}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
