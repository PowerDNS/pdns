#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "base64.hh"
#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include "base32.hh"
#include "dnssecinfra.hh"

#include "dns_random.hh"
#include "gss_context.hh"

StatBag S;

int main(int argc, char** argv)
try
{
  if(argc < 4) {
    cerr<<"Syntax: saxfr IP-address port zone [showdetails] [showflags] [unhash] [gss:remote-principal] [tsig:keyname:algo:secret]"<<endl;
    exit(EXIT_FAILURE);
  }

  bool showdetails=false;
  bool showflags=false;
  bool unhash=false;
  bool gss=false;
  bool tsig=false;
  TSIGHashEnum tsig_algo;
  DNSName tsig_key;
  string tsig_secret;
  string tsigprevious;
  string remote_principal;

  if (argc > 4) {
    for(int i=4; i<argc; i++) {
      if (strcmp(argv[i], "showdetails") == 0)
        showdetails=true;
      if (strcmp(argv[i], "showflags") == 0)
        showflags=true;
      if (strcmp(argv[i], "unhash") == 0)
        unhash=true;
      if (strncmp(argv[i], "gss:",4) == 0) {
        gss=true;
        tsig=true;
        tsig_algo=TSIG_GSS;
        remote_principal = string(argv[i]+4);
        if (remote_principal.empty()) {
          cerr<<"Remote principal is required"<<endl;
          exit(EXIT_FAILURE);
        }
      }
      if (strncmp(argv[i], "tsig:",5) == 0) {
        vector<string> parts;
        tsig=true;
        stringtok(parts, argv[i], ":");
        if (parts.size()!=4) {
          cerr<<"Invalid syntax for tsig"<<endl;
          exit(EXIT_FAILURE);
        }
        if (!getTSIGHashEnum(DNSName(parts[2]), tsig_algo)) {
          cerr<<"Cannot understand TSIG algorithm '"<<parts[1]<<"'"<<endl;
          exit(EXIT_FAILURE);
        }
        tsig_key = DNSName(parts[1]);
        if (tsig_key == DNSName()) {
          cerr<<"Key name must be set for tsig"<<endl;
          exit(EXIT_FAILURE);
        }
        if (B64Decode(parts[3], tsig_secret)) {
          cerr<<"Secret must be base64 encoded"<<endl;
          exit(EXIT_FAILURE);
        }
        if (tsig_secret.size()==0) {
          cerr<<"Secret must be set for tsig"<<endl;
          exit(EXIT_FAILURE);
        }
      }
    }
  }

  reportAllTypes();

  vector<uint8_t> packet;
  uint16_t len;
  ComboAddress dest(argv[1] + (*argv[1]=='@'), atoi(argv[2]));
  Socket sock(dest.sin4.sin_family, SOCK_STREAM);
  sock.connect(dest);

  if (gss) {
#ifndef ENABLE_GSS_TSIG
    cerr<<"No GSS support compiled in"<<endl;
    exit(EXIT_FAILURE);
#else
    string input,output;
    GssContext gssctx;
    gssctx.generateLabel(argv[3]);
    gssctx.setPeerPrincipal(remote_principal);

    while(gssctx.init(input, output) && gssctx.valid() == false) {
      input="";
      DNSPacketWriter pwtkey(packet, gssctx.getLabel(), QType::TKEY, QClass::ANY);
      TKEYRecordContent tkrc;
      tkrc.d_algo = DNSName("gss-tsig.");
      tkrc.d_inception = time((time_t*)NULL);
      tkrc.d_expiration = tkrc.d_inception+15;
      tkrc.d_mode = 3;
      tkrc.d_error = 0;
      tkrc.d_keysize = output.size();
      tkrc.d_key = output;
      tkrc.d_othersize = 0;
      pwtkey.getHeader()->id = dns_random_uint16();
      pwtkey.startRecord(gssctx.getLabel(), QType::TKEY, 3600, QClass::ANY, DNSResourceRecord::ADDITIONAL, false);
      tkrc.toPacket(pwtkey);
      pwtkey.commit();
      for(const string& msg :  gssctx.getErrorStrings()) {
        cerr<<msg<<endl;
      }

      len = htons(packet.size());
      if(sock.write((char *) &len, 2) != 2)
        throw PDNSException("tcp write failed");
      sock.writen(string((char*)&packet[0], packet.size()));
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

      MOADNSParser mdp(false, string(creply.get(), len));
       if (mdp.d_header.rcode != 0) {
         throw PDNSException(string("Remote server refused: ") + std::to_string(mdp.d_header.rcode));
       }
       for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {
         if(i->first.d_type != QType::TKEY) continue;
         // recover TKEY record
         tkrc = TKEYRecordContent(i->first.d_content->getZoneRepresentation());
         input = tkrc.d_key;
       }
    }

    if (gssctx.valid() == false) {
      cerr<<"Could not create GSS context"<<endl;
      exit(EXIT_FAILURE);
    }

    tsig_key = DNSName(gssctx.getLabel());
#endif
  }

  DNSPacketWriter pw(packet, DNSName(argv[3]), 252);

  pw.getHeader()->id = dns_random_uint16();

  if (tsig) {
    TSIGRecordContent trc;
    trc.d_algoName = getTSIGAlgoName(tsig_algo);
    trc.d_time = time((time_t*)NULL);
    trc.d_fudge = 300;
    trc.d_origID=ntohs(pw.getHeader()->id);
    trc.d_eRcode=0;
    addTSIG(pw, trc, tsig_key, tsig_secret, "", false);
  }

  len = htons(packet.size());
  if(sock.write((char *) &len, 2) != 2)
    throw PDNSException("tcp write failed");

  sock.writen(string(packet.begin(), packet.end()));

  bool isNSEC3 = false;
  int soacount=0;
  vector<pair<DNSName,string> > records;
  set<DNSName> labels;
  map<string,DNSName> hashes;
  NSEC3PARAMRecordContent ns3pr;

  while(soacount<2) {
    TSIGRecordContent trc;

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

    MOADNSParser mdp(false, string(creply.get(), len));
    if (mdp.d_header.rcode != 0) {
      throw PDNSException(string("Remote server refused: ") + std::to_string(mdp.d_header.rcode));
    }
    for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i!=mdp.d_answers.end(); ++i) {
      if (i->first.d_type == QType::TSIG) {
        string message;
        if (!tsig) {
          std::cerr<<"Unexpected TSIG signature in data"<<endl;
        }
        trc = TSIGRecordContent(i->first.d_content->getZoneRepresentation());
        continue;
      }
      if(i->first.d_type == QType::SOA)
      {
        ++soacount;
      }
      else if (i->first.d_type == QType::NSEC3PARAM) {
          ns3pr = NSEC3PARAMRecordContent(i->first.d_content->getZoneRepresentation());
          isNSEC3 = true;
      }

      ostringstream o;
      o<<"\t"<<i->first.d_ttl<<"\tIN\t"<<DNSRecordContent::NumberToType(i->first.d_type);
      if(showdetails)
      {
        o<<"\t"<<i->first.d_content->getZoneRepresentation();
      }
      else if(i->first.d_type == QType::RRSIG)
      {
        string zoneRep = i->first.d_content->getZoneRepresentation();
        vector<string> parts;
        stringtok(parts, zoneRep);
        o<<"\t"<<parts[0]<<" "<<parts[1]<<" "<<parts[2]<<" "<<parts[3]<<" [expiry] [inception] [keytag] "<<parts[7]<<" ...";
      }
      else if(i->first.d_type == QType::NSEC3)
      {
        string zoneRep = i->first.d_content->getZoneRepresentation();
        vector<string> parts;
        stringtok(parts, zoneRep);
        o<<"\t"<<parts[0]<<" ";
        if (showflags)
          o<<parts[1];
        else
          o<<"[flags]";
        o<<" "<<parts[2]<<" "<<parts[3]<<" "<<"[next owner]";
        for(vector<string>::iterator iter = parts.begin()+5; iter != parts.end(); ++iter)
          o<<" "<<*iter;
      }
      else if(i->first.d_type == QType::DNSKEY)
      {
        string zoneRep = i->first.d_content->getZoneRepresentation();
        vector<string> parts;
        stringtok(parts, zoneRep);
        o<<"\t"<<parts[0]<<" "<<parts[1]<<" "<<parts[2]<<" ...";
      }
      else
      {
        o<<"\t"<<i->first.d_content->getZoneRepresentation();
      }

      records.push_back(make_pair(i->first.d_name,o.str()));

      DNSName shorter(i->first.d_name);
      do {
        labels.insert(shorter);
        if (shorter == DNSName(argv[3]))
          break;
      }while(shorter.chopOff());

    }
  }

  if (isNSEC3 && unhash)
  {
    string hashed;
    for(const auto &label: labels) {
      hashed=toBase32Hex(hashQNameWithSalt(ns3pr, label));
      hashes.insert(pair<string,DNSName>(hashed, label));
    }
  }

  for(auto &record: records) {
    DNSName label /* FIXME400 rename */=record.first;
    if (isNSEC3 && unhash)
    {
      auto i = hashes.find(label.makeRelative(DNSName(argv[3])).toStringNoDot());
      if (i != hashes.end())
        label=i->second;
    }
    cout<<label.toString()<<record.second<<endl;
  }

}
catch(PDNSException &e2) {
  cerr<<"Fatal: "<<e2.reason<<endl;
}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
