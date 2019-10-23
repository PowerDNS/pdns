#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dnsparser.hh"
#include "dnsrecords.hh"
#include "dnswriter.hh"
#include "ednsoptions.hh"
#include "ednssubnet.hh"
#include "misc.hh"
#include "sstuff.hh"
#include "statbag.hh"
#include <boost/array.hpp>

#ifdef HAVE_LIBCURL
#include "minicurl.hh"
#endif

StatBag S;

bool hidettl = false;

string ttl(uint32_t ttl)
{
  if (hidettl)
    return "[ttl]";
  else
    return std::to_string(ttl);
}

void usage()
{
  cerr << "sdig" << endl;
  cerr << "Syntax: sdig IP-ADDRESS-OR-DOH-URL PORT QUESTION QUESTION-TYPE "
          "[dnssec] [ednssubnet SUBNET/MASK] [hidesoadetails] [hidettl] "
          "[recurse] [showflags] [tcp] [xpf XPFDATA] [class CLASSNUM]"
       << endl;
}

const string nameForClass(uint16_t qclass, uint16_t qtype)
{
  if (qtype == QType::OPT)
    return "IN";

  switch (qclass) {
  case QClass::IN:
    return "IN";
  case QClass::CHAOS:
    return "CHAOS";
  case QClass::NONE:
    return "NONE";
  case QClass::ANY:
    return "ANY";
  default:
    return string("CLASS") + std::to_string(qclass);
  }
}

void fillPacket(vector<uint8_t>& packet, const string& q, const string& t,
  bool dnssec, const boost::optional<Netmask> ednsnm,
  bool recurse, uint16_t xpfcode, uint16_t xpfversion,
  uint64_t xpfproto, char* xpfsrc, char* xpfdst,
  uint16_t qclass)
{
  DNSPacketWriter pw(packet, DNSName(q), DNSRecordContent::TypeToNumber(t), qclass);

  if (dnssec || ednsnm || getenv("SDIGBUFSIZE")) {
    char* sbuf = getenv("SDIGBUFSIZE");
    int bufsize;
    if (sbuf)
      bufsize = atoi(sbuf);
    else
      bufsize = 2800;
    DNSPacketWriter::optvect_t opts;
    if (ednsnm) {
      EDNSSubnetOpts eo;
      eo.source = *ednsnm;
      opts.push_back(
        make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(eo)));
    }

    pw.addOpt(bufsize, 0, dnssec ? EDNSOpts::DNSSECOK : 0, opts);
    pw.commit();
  }

  if (xpfcode) {
    ComboAddress src(xpfsrc), dst(xpfdst);
    pw.startRecord(DNSName("."), xpfcode, 0, QClass::IN, DNSResourceRecord::ADDITIONAL);
    // xpf->toPacket(pw);
    pw.xfr8BitInt(xpfversion);
    pw.xfr8BitInt(xpfproto);
    pw.xfrCAWithoutPort(xpfversion, src);
    pw.xfrCAWithoutPort(xpfversion, dst);
    pw.xfrCAPort(src);
    pw.xfrCAPort(dst);
    pw.commit();
  }

  if (recurse) {
    pw.getHeader()->rd = true;
  }
}

void printReply(const string& reply, bool showflags, bool hidesoadetails)
{
  MOADNSParser mdp(false, reply);
  cout << "Reply to question for qname='" << mdp.d_qname.toString()
       << "', qtype=" << DNSRecordContent::NumberToType(mdp.d_qtype) << endl;
  cout << "Rcode: " << mdp.d_header.rcode << " ("
       << RCode::to_s(mdp.d_header.rcode) << "), RD: " << mdp.d_header.rd
       << ", QR: " << mdp.d_header.qr;
  cout << ", TC: " << mdp.d_header.tc << ", AA: " << mdp.d_header.aa
       << ", opcode: " << mdp.d_header.opcode << endl;

  for (MOADNSParser::answers_t::const_iterator i = mdp.d_answers.begin();
       i != mdp.d_answers.end(); ++i) {
    cout << i->first.d_place - 1 << "\t" << i->first.d_name.toString() << "\t"
         << nameForClass(i->first.d_class, i->first.d_type) << "\t"
         << DNSRecordContent::NumberToType(i->first.d_type);
    if (i->first.d_class == QClass::IN) {
      if (i->first.d_type == QType::RRSIG) {
        string zoneRep = i->first.d_content->getZoneRepresentation();
        vector<string> parts;
        stringtok(parts, zoneRep);
        cout << "\t" << ttl(i->first.d_ttl) << "\t" << parts[0] << " "
             << parts[1] << " " << parts[2] << " " << parts[3]
             << " [expiry] [inception] [keytag] " << parts[7] << " ...\n";
        continue;
      }
      if (!showflags && i->first.d_type == QType::NSEC3) {
        string zoneRep = i->first.d_content->getZoneRepresentation();
        vector<string> parts;
        stringtok(parts, zoneRep);
        cout << "\t" << ttl(i->first.d_ttl) << "\t" << parts[0] << " [flags] "
             << parts[2] << " " << parts[3] << " " << parts[4];
        for (vector<string>::iterator iter = parts.begin() + 5;
             iter != parts.end(); ++iter)
          cout << " " << *iter;
        cout << "\n";
        continue;
      }
      if (i->first.d_type == QType::DNSKEY) {
        string zoneRep = i->first.d_content->getZoneRepresentation();
        vector<string> parts;
        stringtok(parts, zoneRep);
        cout << "\t" << ttl(i->first.d_ttl) << "\t" << parts[0] << " "
             << parts[1] << " " << parts[2] << " ...\n";
        continue;
      }
      if (i->first.d_type == QType::SOA && hidesoadetails) {
        string zoneRep = i->first.d_content->getZoneRepresentation();
        vector<string> parts;
        stringtok(parts, zoneRep);
        cout << "\t" << ttl(i->first.d_ttl) << "\t" << parts[0] << " "
             << parts[1] << " [serial] " << parts[3] << " " << parts[4] << " "
             << parts[5] << " " << parts[6] << "\n";
        continue;
      }
    }
    cout << "\t" << ttl(i->first.d_ttl) << "\t"
         << i->first.d_content->getZoneRepresentation() << "\n";
  }

  EDNSOpts edo;
  if (getEDNSOpts(mdp, &edo)) {
    //    cerr<<"Have "<<edo.d_options.size()<<" options!"<<endl;
    for (vector<pair<uint16_t, string>>::const_iterator iter = edo.d_options.begin();
         iter != edo.d_options.end(); ++iter) {
      if (iter->first == EDNSOptionCode::ECS) { // 'EDNS subnet'
        EDNSSubnetOpts reso;
        if (getEDNSSubnetOptsFromString(iter->second, &reso)) {
          cerr << "EDNS Subnet response: " << reso.source.toString()
               << ", scope: " << reso.scope.toString()
               << ", family = " << reso.scope.getNetwork().sin4.sin_family
               << endl;
        }
      } else if (iter->first == EDNSOptionCode::PADDING) {
        cerr << "EDNS Padding size: " << (iter->second.size()) << endl;
      } else {
        cerr << "Have unknown option " << (int)iter->first << endl;
      }
    }
  }
}

int main(int argc, char** argv)
try {
  bool dnssec = false;
  bool recurse = false;
  bool tcp = false;
  bool showflags = false;
  bool hidesoadetails = false;
  bool doh = false;
  boost::optional<Netmask> ednsnm;
  uint16_t xpfcode = 0, xpfversion = 0, xpfproto = 0;
  char *xpfsrc = NULL, *xpfdst = NULL;
  uint16_t qclass = QClass::IN;

  for (int i = 1; i < argc; i++) {
    if ((string)argv[i] == "--help") {
      usage();
      exit(EXIT_SUCCESS);
    }

    if ((string)argv[i] == "--version") {
      cerr << "sdig " << VERSION << endl;
      exit(EXIT_SUCCESS);
    }
  }

  if (argc < 5) {
    usage();
    exit(EXIT_FAILURE);
  }

  reportAllTypes();

  if (argc > 5) {
    for (int i = 5; i < argc; i++) {
      if (strcmp(argv[i], "dnssec") == 0)
        dnssec = true;
      if (strcmp(argv[i], "recurse") == 0)
        recurse = true;
      if (strcmp(argv[i], "showflags") == 0)
        showflags = true;
      if (strcmp(argv[i], "hidesoadetails") == 0)
        hidesoadetails = true;
      if (strcmp(argv[i], "hidettl") == 0)
        hidettl = true;
      if (strcmp(argv[i], "tcp") == 0)
        tcp = true;
      if (strcmp(argv[i], "ednssubnet") == 0) {
        if (argc < i + 2) {
          cerr << "ednssubnet needs an argument" << endl;
          exit(EXIT_FAILURE);
        }
        ednsnm = Netmask(argv[++i]);
      }
      if (strcmp(argv[i], "xpf") == 0) {
        if (argc < i + 6) {
          cerr << "xpf needs five arguments" << endl;
          exit(EXIT_FAILURE);
        }
        xpfcode = atoi(argv[++i]);
        xpfversion = atoi(argv[++i]);
        xpfproto = atoi(argv[++i]);
        xpfsrc = argv[++i];
        xpfdst = argv[++i];
      }
      if (strcmp(argv[i], "class") == 0) {
        if (argc < i+2) {
          cerr << "class needs an argument"<<endl;
          exit(EXIT_FAILURE);
        }
        qclass = atoi(argv[++i]);
      }
    }
  }

  string reply;
  ComboAddress dest;
  if (*argv[1] == 'h') {
    doh = true;
  } else {
    dest = ComboAddress(argv[1] + (*argv[1] == '@'), atoi(argv[2]));
  }

  string name = string(argv[3]);
  string type = string(argv[4]);

  vector<pair<string, string>> questions;
  if (name == "-" && type == "-") {
    if (!tcp) {
      throw PDNSException("multi-query from stdin only supported for tcp");
    }
    string line;
    while (getline(std::cin, line)) {
      auto fields = splitField(line, ' ');

      questions.push_back(make_pair(fields.first, fields.second));
    }
  } else {
    questions.push_back(make_pair(name, type));
  }

  if (doh) {
#ifdef HAVE_LIBCURL
    vector<uint8_t> packet;
    fillPacket(packet, name, type, dnssec, ednsnm, recurse, xpfcode, xpfversion,
      xpfproto, xpfsrc, xpfdst, qclass);
    MiniCurl mc;
    MiniCurl::MiniCurlHeaders mch;
    mch.insert(std::make_pair("Content-Type", "application/dns-message"));
    mch.insert(std::make_pair("Accept", "application/dns-message"));
    string question(packet.begin(), packet.end());
    reply = mc.postURL(argv[1], question, mch);
    printReply(reply, showflags, hidesoadetails);
#else
    throw PDNSException("please link sdig against libcurl for DoH support");
#endif
  } else if (tcp) {
    Socket sock(dest.sin4.sin_family, SOCK_STREAM);
    sock.connect(dest);
    for (const auto& it : questions) {
      vector<uint8_t> packet;
      fillPacket(packet, it.first, it.second, dnssec, ednsnm, recurse, xpfcode,
        xpfversion, xpfproto, xpfsrc, xpfdst, qclass);

      uint16_t len = htons(packet.size());
      if (sock.write((const char *)&len, 2) != 2)
        throw PDNSException("tcp write failed");
      string question(packet.begin(), packet.end());
      sock.writen(question);
    }
    for (size_t i = 0; i < questions.size(); i++) {
      uint16_t len;
      if (sock.read((char *)&len, 2) != 2)
        throw PDNSException("tcp read failed");

      len = ntohs(len);
      char* creply = new char[len];
      int n = 0;
      int numread;
      while (n < len) {
        numread = sock.read(creply + n, len - n);
        if (numread < 0)
          throw PDNSException("tcp read failed");
        n += numread;
      }

      reply = string(creply, len);
      delete[] creply;
      printReply(reply, showflags, hidesoadetails);
    }
  } else // udp
  {
    vector<uint8_t> packet;
    fillPacket(packet, name, type, dnssec, ednsnm, recurse, xpfcode, xpfversion,
      xpfproto, xpfsrc, xpfdst, qclass);
    string question(packet.begin(), packet.end());
    Socket sock(dest.sin4.sin_family, SOCK_DGRAM);
    sock.sendTo(question, dest);
    int result = waitForData(sock.getHandle(), 10);
    if (result < 0)
      throw std::runtime_error("Error waiting for data: " + stringerror());
    if (!result)
      throw std::runtime_error("Timeout waiting for data");
    sock.recvFrom(reply, dest);
    printReply(reply, showflags, hidesoadetails);
  }

} catch (std::exception& e) {
  cerr << "Fatal: " << e.what() << endl;
} catch (PDNSException& e) {
  cerr << "Fatal: " << e.reason << endl;
}
