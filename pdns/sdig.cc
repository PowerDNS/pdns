#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"

/** Write only packet generator */
class DNSPacketGenerator
{
public:
  DNSPacketGenerator(const string& qname, uint16_t qtype); // there is always a question
  const string getPacket();
  dnsheader d_dnsheader;
private:
  string d_content;
};

const string EncodeDNSLabel(const string& input)
{
  typedef vector<string> parts_t;
  parts_t parts;
  stringtok(parts,input,".");

  string ret;
  for(parts_t::const_iterator i=parts.begin(); i!=parts.end(); ++i) {
    ret.append(1,(char)i->length());
    ret.append(*i);
  }
  ret.append(1,(char)0);
  return ret;
    
}

DNSPacketGenerator::DNSPacketGenerator(const string& qname, uint16_t qtype)
{
  memset(&d_dnsheader, 0, sizeof(d_dnsheader));
  d_dnsheader.id=random();
  d_dnsheader.qdcount=htons(1);

  d_content=EncodeDNSLabel(qname);
  qtype=htons(qtype);
  d_content.append((char*)&qtype, 2);
  qtype=htons(1);
  d_content.append((char*)&qtype,2);
}

const string DNSPacketGenerator::getPacket()
{
  return string((char*)&d_dnsheader, ((char*)&d_dnsheader)+sizeof(d_dnsheader))+d_content;
}

int main(int argc, char** argv)
try
{
  DNSPacketGenerator dpg(argv[3], atoi(argv[4]));

  Socket sock(InterNetwork, Datagram);
  IPEndpoint dest(argv[1], atoi(argv[2]));
  sock.sendTo(dpg.getPacket(), dest);
  
  string reply;
  sock.recvFrom(reply, dest);

  MOADNSParser mdp(reply);
  cout<<"Reply to question for qname='"<<mdp.d_qname<<"', qtype="<<mdp.d_qtype<<endl;

  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {          
    shared_ptr<PacketReader> pr=mdp.getPacketReader(i->second);
    DNSRecordContent* drc=DNSRecordContent::mastermake(i->first.d_ah, *pr);
    cout<<i->first.d_place<<"\t"<<i->first.d_label<<"\tIN\t"<<drc->getType()<<"\t"<<i->first.d_ttl<<"\t"<<drc->getZoneRepresentation()<<endl;
  }


}
catch(exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}

