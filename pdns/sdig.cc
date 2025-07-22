#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dnsparser.hh"
#include "dnsrecords.hh"
#include "dnswriter.hh"
#include "ednsoptions.hh"
#include "ednssubnet.hh"
#include "ednscookies.hh"
#include "ednsextendederror.hh"
#include "ednszoneversion.hh"
#include "misc.hh"
#include "proxy-protocol.hh"
#include "sstuff.hh"
#include "statbag.hh"
#include <boost/array.hpp>
#include "protozero-trace.hh"

#ifdef HAVE_LIBCURL
#include "minicurl.hh"
#endif

#include "tcpiohandler.hh"

StatBag S;

// Vars below used by tcpiohandler.cc
bool g_verbose = true;

static bool hidettl = false;

static string ttl(uint32_t ttl)
{
  if (hidettl)
    return "[ttl]";
  else
    return std::to_string(ttl);
}

static void usage()
{
  cerr << "sdig" << endl;
  cerr << "Syntax: sdig IP-ADDRESS-OR-DOH-URL PORT QNAME QTYPE "
          "[dnssec] [ednssubnet SUBNET/MASK] [hidesoadetails] [hidettl] [recurse] [showflags] "
          "[tcp] [dot] [insecure] [fastOpen] [subjectName name] [caStore file] [tlsProvider openssl|gnutls] "
          "[proxy UDP(0)/TCP(1) SOURCE-IP-ADDRESS-AND-PORT DESTINATION-IP-ADDRESS-AND-PORT] "
          "[cookie -/HEX] "
          "[dumpluaraw] [opcode OPNUM] "
          "[traceid -/HEX]"
       << endl;
}

static const string nameForClass(QClass qclass, uint16_t qtype)
{
  if (qtype == QType::OPT)
    return "IN";

  return qclass.toString();
}

using OpenTelemetryData = std::optional<std::pair<pdns::trace::TraceID, pdns::trace::SpanID>>;

static std::unordered_set<uint16_t> s_expectedIDs;

static void fillPacket(vector<uint8_t>& packet, const string& q, const string& t,
                       bool dnssec, const std::optional<Netmask>& ednsnm,
                       bool zoneversion,
                       bool recurse, QClass qclass, uint8_t opcode, uint16_t qid, const std::optional<string>& cookie,
                       OpenTelemetryData& otids)
{
  DNSPacketWriter pwriter(packet, DNSName(q), DNSRecordContent::TypeToNumber(t), qclass, opcode);

  char* env_sdigbufsize = getenv("SDIGBUFSIZE"); // NOLINT(concurrency-mt-unsafe)
  if (dnssec || ednsnm || env_sdigbufsize != nullptr || cookie || otids || zoneversion) { // NOLINT(concurrency-mt-unsafe) we're single threaded
    int bufsize = 2800;
    if (env_sdigbufsize != nullptr) {
      bufsize = atoi(env_sdigbufsize);
    }
    DNSPacketWriter::optvect_t opts;
    if (ednsnm) {
      EDNSSubnetOpts eo;
      eo.setSource(*ednsnm);
      opts.emplace_back(EDNSOptionCode::ECS, eo.makeOptString());
    }
    if (cookie) {
      EDNSCookiesOpt cookieOpt;
      if (*cookie == "-") {
        cookieOpt.makeClientCookie();
      }
      else {
        string unhex = makeBytesFromHex(*cookie);
        if (!cookieOpt.makeFromString(unhex)) {
          cerr << "Malformed cookie in argument list, adding anyway" << endl;
        }
      }
      opts.emplace_back(EDNSOptionCode::COOKIE, cookieOpt.makeOptString());
    }
    if (otids) {
      const auto traceid = otids->first;
      const auto spanid = otids->second;
      std::array<uint8_t, pdns::trace::EDNSOTTraceRecord::fullSize> data{};
      pdns::trace::EDNSOTTraceRecord record{data.data()};
      record.setVersion(0);
      record.setTraceID(traceid);
      record.setSpanID(spanid);
      opts.emplace_back(EDNSOptionCode::OTTRACEIDS, std::string_view(reinterpret_cast<const char*>(data.data()), data.size())); // NOLINT
    }
    if (zoneversion) {
      opts.emplace_back(EDNSOptionCode::ZONEVERSION, "");
    }

    pwriter.addOpt(bufsize, 0, dnssec ? EDNSOpts::DNSSECOK : 0, opts);
    pwriter.commit();
  }

  if (recurse) {
    pwriter.getHeader()->rd = true;
  }

  pwriter.getHeader()->id = htons(qid);
}

static void printReply(const string& reply, bool showflags, bool hidesoadetails, bool dumpluaraw, bool ignoreId = false)
{
  MOADNSParser mdp(false, reply);

  if (!ignoreId && (s_expectedIDs.count(ntohs(mdp.d_header.id)) == 0U)) {
    cout << "ID " << ntohs(mdp.d_header.id) << " was not expected, this response was not meant for us!"<<endl;
  }
  s_expectedIDs.erase(ntohs(mdp.d_header.id));

  cout << (mdp.d_header.qr ? "Reply to question" : "Question") << " for qname='" << mdp.d_qname.toString()
       << "', qtype=" << DNSRecordContent::NumberToType(mdp.d_qtype);

  if (ignoreId) {
    // if we did not generate the ID, the user might be interested in seeing it
    cout << ", ID=" << ntohs(mdp.d_header.id);
  }

  cout << endl;
  EDNSOpts edo{};
  bool hasEDNS = getEDNSOpts(mdp, &edo);

  if (hasEDNS) {
    uint16_t ercode = edo.d_extRCode << 4 | mdp.d_header.rcode;
    cout << "Rcode: " << ercode << " (" << ERCode::to_s(ercode);
  }
  else {
    cout << "Rcode: " << mdp.d_header.rcode << " (" << RCode::to_s(mdp.d_header.rcode);
  }

  cout << "), RD: " << mdp.d_header.rd
       << ", QR: " << mdp.d_header.qr;
  cout << ", TC: " << mdp.d_header.tc << ", AA: " << mdp.d_header.aa
       << ", opcode: " << mdp.d_header.opcode << endl;

  for (MOADNSParser::answers_t::const_iterator i = mdp.d_answers.begin();
       i != mdp.d_answers.end(); ++i) {
    cout << i->d_place - 1 << "\t" << i->d_name.toString() << "\t"
         << ttl(i->d_ttl) << "\t" << nameForClass(i->d_class, i->d_type) << "\t"
         << DNSRecordContent::NumberToType(i->d_type);
    if (dumpluaraw) {
      cout<<"\t"<< makeLuaString(i->getContent()->serialize(DNSName(), true))<<endl;
      continue;
    }
    if (i->d_class == QClass::IN) {
      if (i->d_type == QType::RRSIG) {
        string zoneRep = i->getContent()->getZoneRepresentation();
        vector<string> parts;
        stringtok(parts, zoneRep);
        cout << "\t" << parts[0] << " "
             << parts[1] << " " << parts[2] << " " << parts[3]
             << " [expiry] [inception] [keytag] " << parts[7] << " ...\n";
        continue;
      }
      if (!showflags && i->d_type == QType::NSEC3) {
        string zoneRep = i->getContent()->getZoneRepresentation();
        vector<string> parts;
        stringtok(parts, zoneRep);
        cout << "\t" << parts[0] << " [flags] "
             << parts[2] << " " << parts[3] << " " << parts[4];
        for (vector<string>::iterator iter = parts.begin() + 5;
             iter != parts.end(); ++iter)
          cout << " " << *iter;
        cout << "\n";
        continue;
      }
      if (i->d_type == QType::DNSKEY) {
        string zoneRep = i->getContent()->getZoneRepresentation();
        vector<string> parts;
        stringtok(parts, zoneRep);
        cout << "\t" << parts[0] << " "
             << parts[1] << " " << parts[2] << " ...\n";
        continue;
      }
      if (i->d_type == QType::SOA && hidesoadetails) {
        string zoneRep = i->getContent()->getZoneRepresentation();
        vector<string> parts;
        stringtok(parts, zoneRep);
        cout << "\t" << parts[0] << " "
             << parts[1] << " [serial] " << parts[3] << " " << parts[4] << " "
             << parts[5] << " " << parts[6] << "\n";
        continue;
      }
    }
    cout << "\t" << i->getContent()->getZoneRepresentation() << "\n";
  }

  if (hasEDNS) {
    for (const auto& iter : edo.d_options) {
      if (iter.first == EDNSOptionCode::ECS) { // 'EDNS subnet'
        EDNSSubnetOpts reso;
        if (EDNSSubnetOpts::getFromString(iter.second, &reso)) {
          cerr << "EDNS Subnet response: " << reso.getSource().toString()
               << ", scope: " << reso.getScope().toString()
               << ", family = " << std::to_string(reso.getFamily())
               << endl;
        }
      }
      else if (iter.first == EDNSOptionCode::COOKIE) {
        EDNSCookiesOpt cookie(iter.second);
        auto client = cookie.getClient();
        auto server = cookie.getServer();
        auto dump = makeHexDump(client, "") + makeHexDump(server, "");
        if (cookie.isWellFormed()) {
          cerr << "EDNS Cookie response: " << dump << endl;
        }
        else {
          cerr << "EDNS Cookie response malformed: " << dump << endl;
        }
      } else if (iter.first == EDNSOptionCode::PADDING) {
        cerr << "EDNS Padding size: " << iter.second.size() << endl;
      } else if (iter.first == EDNSOptionCode::EXTENDEDERROR) {
        EDNSExtendedError eee;
        if (getEDNSExtendedErrorOptFromString(iter.second, eee)) {
          cerr << "EDNS Extended Error response: " << eee.infoCode << "/" << eee.extraText << endl;
        }
      } else if (iter.first == EDNSOptionCode::ZONEVERSION) {
        EDNSZoneVersion zoneversion{};
        if (getEDNSZoneVersionFromString(iter.second, zoneversion)) {
          if (zoneversion.type == 0) { // FIXME enum
            cerr << "EDNS Zone Version (SOA serial) for labelcount " << (int)zoneversion.labelcount << ": " << zoneversion.version << endl;
          } else {
            cerr << "EDNS Zone Version (type " << (int)zoneversion.type << ") for labelcount " << (int)zoneversion.labelcount << ": " << zoneversion.version << endl;
          }
        }
      } else {
        cerr << "Have unknown option " << (int)iter.first << endl;
      }
    }
  }
}


// accessing `argv[i]` triggers `cppcoreguidelines-pro-bounds-pointer-arithmetic`
// NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)

int main(int argc, char** argv) // NOLINT(readability-function-cognitive-complexity)
try {
  /* default timeout of 10s */
  struct timeval timeout{10,0};
  bool dnssec = false;
  bool recurse = false;
  bool tcp = false;
  bool showflags = false;
  bool hidesoadetails = false;
  bool doh = false;
  bool dot = false;
  bool fastOpen = false;
  bool insecureDoT = false;
  bool fromstdin = false;
  std::optional<Netmask> ednsnm;
  QClass qclass = QClass::IN;
  uint8_t opcode = 0;
  string proxyheader;
  string subjectName;
  string caStore;
  string tlsProvider = "openssl";
  bool dumpluaraw = false;
  std::optional<string> cookie;
  OpenTelemetryData otdata;
  bool zoneversion = false;

  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic, concurrency-mt-unsafe) it's the argv API and we're single-threaded
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
      else if (strcmp(argv[i], "recurse") == 0)
        recurse = true;
      else if (strcmp(argv[i], "showflags") == 0)
        showflags = true;
      else if (strcmp(argv[i], "hidesoadetails") == 0)
        hidesoadetails = true;
      else if (strcmp(argv[i], "hidettl") == 0)
        hidettl = true;
      else if (strcmp(argv[i], "tcp") == 0)
        tcp = true;
      else if (strcmp(argv[i], "dot") == 0)
        dot = true;
      else if (strcmp(argv[i], "insecure") == 0)
        insecureDoT = true;
      else if (strcmp(argv[i], "fastOpen") == 0)
        fastOpen = true;
      else if (strcmp(argv[i], "ednssubnet") == 0) {
        if (argc < i + 2) {
          cerr << "ednssubnet needs an argument" << endl;
          exit(EXIT_FAILURE);
        }
        ednsnm = Netmask(argv[++i]);
      }
      else if (strcmp(argv[i], "class") == 0) {
        if (argc < i+2) {
          cerr << "class needs an argument"<<endl;
          exit(EXIT_FAILURE);
        }
        qclass = atoi(argv[++i]);
      }
      else if (strcmp(argv[i], "opcode") == 0) {
        if (argc < i+2) {
          cerr << "opcode needs an argument"<<endl;
          exit(EXIT_FAILURE);
        }
        opcode = atoi(argv[++i]);
      }
      else if (strcmp(argv[i], "subjectName") == 0) {
        if (argc < i + 2) {
          cerr << "subjectName needs an argument"<<endl;
          exit(EXIT_FAILURE);
        }
        subjectName = argv[++i];
      }
      else if (strcmp(argv[i], "caStore") == 0) {
        if (argc < i + 2) {
          cerr << "caStore needs an argument"<<endl;
          exit(EXIT_FAILURE);
        }
        caStore = argv[++i];
      }
      else if (strcmp(argv[i], "tlsProvider") == 0) {
        if (argc < i + 2) {
          cerr << "tlsProvider needs an argument"<<endl;
          exit(EXIT_FAILURE);
        }
        tlsProvider = argv[++i];
      }
      else if (strcmp(argv[i], "proxy") == 0) {
        if(argc < i+4) {
          cerr<<"proxy needs three arguments"<<endl;
          exit(EXIT_FAILURE);
        }
        bool ptcp = atoi(argv[++i]);
        ComboAddress src(argv[++i]);
        ComboAddress dest(argv[++i]);
        proxyheader = makeProxyHeader(ptcp, src, dest, {});
      }
      else if (strcmp(argv[i], "cookie") == 0) {
        if (argc < i + 2) {
          cerr << "cookie needs an argument"<<endl;
          exit(EXIT_FAILURE);
        }
        cookie = argv[++i];
      }
      else if (strcmp(argv[i], "dumpluaraw") == 0) {
        dumpluaraw = true;
      }
      else if (strcmp(argv[i], "traceid") == 0) {
        if (argc < i + 2) {
          cerr << "traceid needs an argument" << endl;
          exit(EXIT_FAILURE);
        }
        auto traceIDArg = std::string(argv[++i]);
        pdns::trace::TraceID traceid{};
        if (traceIDArg == "-") {
          pdns::trace::random(traceid);
        }
        else {
          auto traceIDStr = makeBytesFromHex(traceIDArg);
          if (traceIDStr.size() > traceid.size()) {
            cerr << "Maximum length of traceid is " << traceid.size() << " bytes" << endl;
            exit(EXIT_FAILURE);
          }
          traceIDStr.resize(traceid.size());
          pdns::trace::fill(traceid, traceIDStr);
        }
        pdns::trace::SpanID spanid{}; // default: all zero, so no parent
        otdata = std::make_pair(traceid, spanid);
      }
      else if (strcmp(argv[i], "zoneversion") == 0) {
        zoneversion = true;
      }
      else {
        cerr << argv[i] << ": unknown argument" << endl;
        exit(EXIT_FAILURE);
      }
    }
  }
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic, concurrency-mt-unsafe)

  if (dot) {
    tcp = true;
  }

#ifndef HAVE_DNS_OVER_TLS
  if (dot) {
    cerr << "DoT requested but not compiled in" << endl;
    exit(EXIT_FAILURE);
  }
#endif

  string reply;
  ComboAddress dest;
  if (*argv[1] == 'h') {
    doh = true;
  } else if(strcmp(argv[1], "stdin") == 0) {
    fromstdin = true;
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

      questions.emplace_back(fields.first, fields.second);
    }
  } else {
    questions.emplace_back(name, type);
  }

  if (doh) {
#ifdef HAVE_LIBCURL
    vector<uint8_t> packet;
    s_expectedIDs.insert(0);
    fillPacket(packet, name, type, dnssec, ednsnm, zoneversion, recurse, qclass, opcode, 0, cookie, otdata);
    MiniCurl mc;
    MiniCurl::MiniCurlHeaders mch;
    mch.emplace("Content-Type", "application/dns-message");
    mch.emplace("Accept", "application/dns-message");
    string question(packet.begin(), packet.end());
    // FIXME: how do we use proxyheader here?
    reply = mc.postURL(argv[1], question, mch, timeout.tv_sec, fastOpen);
    printReply(reply, showflags, hidesoadetails, dumpluaraw);
#else
    throw PDNSException("please link sdig against libcurl for DoH support");
#endif
  } else if (fromstdin) {
    std::istreambuf_iterator<char> begin(std::cin), end;
    reply = string(begin, end);

    ComboAddress source, destination;
    bool wastcp;
    bool proxy = false;
    std::vector<ProxyProtocolValue> ignoredValues;
    ssize_t offset = parseProxyHeader(reply, proxy, source, destination, wastcp, ignoredValues);
    if (offset && proxy) {
      cout<<"proxy "<<(wastcp ? "tcp" : "udp")<<" headersize="<<offset<<" source="<<source.toStringWithPort()<<" destination="<<destination.toStringWithPort()<<endl;
      reply = reply.substr(offset);
    }

    if (tcp) {
      reply = reply.substr(2);
    }

    printReply(reply, showflags, hidesoadetails, dumpluaraw, true);
  } else if (tcp) {
    std::shared_ptr<TLSCtx> tlsCtx{nullptr};
    if (dot) {
      TLSContextParameters tlsParams;
      tlsParams.d_provider = tlsProvider;
      tlsParams.d_validateCertificates = !insecureDoT;
      tlsParams.d_caStore = caStore;
      tlsCtx = getTLSContext(tlsParams);
    }
    uint16_t counter = 0;
    Socket sock(dest.sin4.sin_family, SOCK_STREAM);
    sock.setNonBlocking();
    setTCPNoDelay(sock.getHandle()); // disable NAGLE, which does not play nicely with delayed ACKs
    TCPIOHandler handler(subjectName, false, sock.releaseHandle(), timeout, std::move(tlsCtx));
    handler.connect(fastOpen, dest, timeout);
    // we are writing the proxyheader inside the TLS connection. Is that right?
    if (proxyheader.size() > 0 && handler.write(proxyheader.data(), proxyheader.size(), timeout) != proxyheader.size()) {
      throw PDNSException("tcp write failed");
    }

    for (const auto& it : questions) {
      vector<uint8_t> packet;
      s_expectedIDs.insert(counter);
      fillPacket(packet, it.first, it.second, dnssec, ednsnm, zoneversion, recurse, qclass, opcode, counter, cookie, otdata);
      counter++;

      // Prefer to do a single write, so that fastopen can send all the data on SYN
      uint16_t len = packet.size();
      string question;
      question.reserve(sizeof(len) + packet.size());
      question.push_back(static_cast<char>(len >> 8));
      question.push_back(static_cast<char>(len & 0xff));
      question.append(packet.begin(), packet.end());
      if (handler.write(question.data(), question.size(), timeout) != question.size()) {
        throw PDNSException("tcp write failed");
      }
    }
    for (size_t i = 0; i < questions.size(); i++) {
      uint16_t len;
      if (handler.read((char *)&len, sizeof(len), timeout) != sizeof(len)) {
        throw PDNSException("tcp read failed");
      }
      len = ntohs(len);
      reply.resize(len);
      if (handler.read(&reply[0], len, timeout) != len) {
        throw PDNSException("tcp read failed");
      }
      printReply(reply, showflags, hidesoadetails, dumpluaraw);
    }
  } else // udp
  {
    vector<uint8_t> packet;
    s_expectedIDs.insert(0);
    fillPacket(packet, name, type, dnssec, ednsnm, zoneversion, recurse, qclass, opcode, 0, cookie, otdata);
    string question(packet.begin(), packet.end());
    Socket sock(dest.sin4.sin_family, SOCK_DGRAM);
    question = proxyheader + question;
    sock.sendTo(question, dest);
    int result = waitForData(sock.getHandle(), timeout.tv_sec, timeout.tv_usec);
    if (result < 0)
      throw std::runtime_error("Error waiting for data: " + stringerror());
    if (!result)
      throw std::runtime_error("Timeout waiting for data");
    sock.recvFrom(reply, dest);
    printReply(reply, showflags, hidesoadetails, dumpluaraw);
  }

} catch (std::exception& e) {
  cerr << "Fatal: " << e.what() << endl;
} catch (PDNSException& e) {
  cerr << "Fatal: " << e.reason << endl;
}

// NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
