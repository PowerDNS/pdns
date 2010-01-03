#include "dnsparser.hh"
#include "dnswriter.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include "md5.hh"
#include "base64.hh"

StatBag S;

string calculateHMAC(const std::string& key_, const std::string& text)
{
  const unsigned char* key=(const unsigned char*)key_.c_str();
  unsigned char keyIpad[64];
  unsigned char keyOpad[64];

  cerr<<"Key length: "<<key_.length()<<", ";
  cerr<<"text length: "<<text.length()<<endl;

  for(unsigned int n=0; n < 64; ++n) {
    if(n < key_.length()) {
      keyIpad[n] = (unsigned char)(key[n] ^ 0x36);
      keyOpad[n] = (unsigned char)(key[n] ^ 0x5c);
    }
    else  {
      keyIpad[n]=0x36;
      keyOpad[n]=0x5c;
    }
  }

  MD5Summer md5_1, md5_2;
  md5_1.feed((const char*)keyIpad, 64);
  md5_1.feed(text);

  md5_2.feed((const char*)keyOpad, 64);
  md5_2.feed(md5_1.get());

  return md5_2.get();
}

int main(int argc, char** argv)
try
{
  reportAllTypes();

  if(argc < 4) {
    cerr<<"tsig-tests: ask a TSIG signed question, verify the TSIG signed answer"<<endl;
    cerr<<"Syntax: tsig IP-address port question question-type\n";
    exit(EXIT_FAILURE);
  }

  vector<uint8_t> packet;
  
  DNSPacketWriter pw(packet, argv[3], DNSRecordContent::TypeToNumber(argv[4]));

  pw.getHeader()->id=htons(0x4831);
  //  pw.setRD(true);
  // 'packet' now contains a packet

  string toSign((char*)&*packet.begin(), (char*)&*packet.end());

  vector<uint8_t> signVect;
  DNSPacketWriter dw(signVect, "", 0);
  dw.xfrLabel("thekey.", false);
  dw.xfr16BitInt(0xff); // class
  dw.xfr32BitInt(0);    // TTL
  dw.xfrLabel("hmac-md5.sig-alg.reg.int.", false);
  uint32_t now = time(0); 
  dw.xfr48BitInt(now);
  dw.xfr16BitInt(300); // fudge
  dw.xfr16BitInt(0); // extended rcode
  dw.xfr16BitInt(0); // length of 'other' data

  const vector<uint8_t>& signRecord=dw.getRecordBeingWritten();
  toSign.append(&*signRecord.begin(), &*signRecord.end());

  string key;
  B64Decode("9R64Ak0LOlUz35oSeH/CnQ==", key);

  string hmac=calculateHMAC(key, toSign);

  pw.startRecord("thekey", QType::TSIG, 0, 0xff, DNSPacketWriter::ADDITIONAL);
  TSIGRecordContent trc;
  trc.d_algoName="hmac-md5.sig-alg.reg.int.";
  trc.d_time=now;
  trc.d_fudge=300;
  trc.d_mac=hmac;
  trc.d_origID=ntohs(pw.getHeader()->id);
  trc.d_eRcode=0;

  trc.toPacket(pw);
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

  shared_ptr<TSIGRecordContent> trc2;
  
  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {          
    cout<<i->first.d_place-1<<"\t"<<i->first.d_label<<"\tIN\t"<<DNSRecordContent::NumberToType(i->first.d_type, i->first.d_class);
    cout<<"\t"<<i->first.d_ttl<<"\t"<< i->first.d_content->getZoneRepresentation()<<"\n";
    
    if(i->first.d_type == QType::TSIG)
      trc2 = boost::dynamic_pointer_cast<TSIGRecordContent>(i->first.d_content);
  }

  if(mdp.getTSIGPos()) {
    reply.resize(mdp.getTSIGPos());
    reply[sizeof(struct dnsheader)-1]--;

    // now sign: the combination of our previous mac, the adjusted 'reply', and the TSIG variables
    // the outcome should be the mac we just stripped off.
    string toSign;
 
    uint16_t len = htons(hmac.length());
    toSign.append((char*)&len, 2);
    toSign.append(hmac);
    toSign.append(reply);

    vector<uint8_t> signVect;
    DNSPacketWriter dw(signVect, "", 0);
    dw.xfrLabel("thekey.", false);
    dw.xfr16BitInt(0xff); // class
    dw.xfr32BitInt(0);    // TTL
    dw.xfrLabel("hmac-md5.sig-alg.reg.int.", false);
    uint32_t now = trc2->d_time; 
    dw.xfr48BitInt(now);
    dw.xfr16BitInt(trc2->d_fudge); // fudge
    dw.xfr16BitInt(trc2->d_eRcode); // extended rcode
    dw.xfr16BitInt(trc2->d_otherData.length()); // length of 'other' data
    //    dw.xfrBlob(trc2->d_otherData);

    const vector<uint8_t>& signRecord=dw.getRecordBeingWritten();
    toSign.append(&*signRecord.begin(), &*signRecord.end());

    string hmac2=calculateHMAC(key, toSign);
    cerr<<"Calculated mac: "<<Base64Encode(hmac2)<<endl;
  }
}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
