#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>

#include "dnsname.hh"
#include "dnsparser.hh"
#include "dnswriter.hh"
#include "ednscookies.hh"
#include "ednsextendederror.hh"
#include "ednsoptions.hh"
#include "ednssubnet.hh"
#include "iputils.hh"

BOOST_AUTO_TEST_SUITE(ednsoptions_cc)

static void getRawQueryWithECSAndCookie(const DNSName& name, const Netmask& ecs, const std::string& clientCookie, const std::string& serverCookie, std::vector<uint8_t>& query)
{
  DNSPacketWriter writer(query, name, QType::A, QClass::IN, 0);
  writer.commit();

  EDNSCookiesOpt cookiesOpt(clientCookie + serverCookie);
  string cookiesOptionStr = cookiesOpt.makeOptString();
  EDNSSubnetOpts ecsOpts;
  ecsOpts.setSource(ecs);
  string origECSOptionStr = ecsOpts.makeOptString();
  DNSPacketWriter::optvect_t opts;
  opts.emplace_back(EDNSOptionCode::COOKIE, cookiesOptionStr);
  opts.emplace_back(EDNSOptionCode::ECS, origECSOptionStr);
  opts.emplace_back(EDNSOptionCode::COOKIE, cookiesOptionStr);
  writer.addOpt(512, 0, 0, opts);
  writer.commit();
}

static std::string getOPTContentFromPacket(const PacketBuffer& packet)
{
  BOOST_REQUIRE(packet.size() >= sizeof(dnsheader));

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  PacketReader reader(std::string_view(reinterpret_cast<const char*>(packet.data()), packet.size()));

  const dnsheader_aligned dnsHeader(packet.data());
  uint16_t qdcount = ntohs(dnsHeader->qdcount);
  uint16_t ancount = ntohs(dnsHeader->ancount);
  uint16_t nscount = ntohs(dnsHeader->nscount);
  uint16_t arcount = ntohs(dnsHeader->arcount);

  for (size_t idx = 0; idx < qdcount; idx++) {
    reader.getName();
    reader.get16BitInt();
    reader.get16BitInt();
  }
  dnsrecordheader recordHeader{};
  std::string blob;
  /* skip AN and NS */
  for (size_t idx = 0; idx < ancount + nscount; idx++) {
    reader.getName();
    reader.getDnsrecordheader(recordHeader);
    reader.xfrBlob(blob);
  }

  /* consume AR, looking for OPT */
  for (size_t idx = 0; idx < arcount; idx++) {
    auto rrname = reader.getName();
    reader.getDnsrecordheader(recordHeader);

    if (!rrname.isRoot() || recordHeader.d_type != QType::OPT) {
      continue;
    }

    reader.xfrBlob(blob);
    return blob;
  }

  throw std::runtime_error("OPT record not found");
}

BOOST_AUTO_TEST_CASE(test_getEDNSOption)
{
  DNSName name("www.powerdns.com.");
  Netmask ecs("127.0.0.1/32");
  vector<uint8_t> query;

  getRawQueryWithECSAndCookie(name, ecs, "deadbeef", "deadbeef", query);

  const dnsheader_aligned dnsHeader(query.data());
  size_t questionLen = query.size();
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  const auto* queryDataAsChar = reinterpret_cast<const char*>(query.data());
  unsigned int consumed = 0;
  DNSName dnsname(queryDataAsChar, questionLen, sizeof(dnsheader), false, nullptr, nullptr, &consumed);

  size_t pos = sizeof(dnsheader) + consumed + 4;
  size_t ecsStartPosition = 0;
  size_t ecsLen = 0;
  /* at least OPT root label (1), type (2), class (2) and ttl (4) + OPT RR rdlen (2) = 11 */
  BOOST_REQUIRE_EQUAL(ntohs(dnsHeader->arcount), 1);
  BOOST_REQUIRE(questionLen > pos + 11);
  /* OPT root label (1) followed by type (2) */
  BOOST_REQUIRE_EQUAL(query.at(pos), 0);
  BOOST_REQUIRE(query.at(pos + 2) == QType::OPT);

  {
    /* invalid */
    BOOST_CHECK_EQUAL(getEDNSOption(nullptr, 0U, EDNSOptionCode::ECS, nullptr, nullptr), EINVAL);
    BOOST_CHECK_EQUAL(getEDNSOption(queryDataAsChar, query.size(), EDNSOptionCode::ECS, nullptr, nullptr), EINVAL);
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  const auto* optRR = reinterpret_cast<const char*>(&query.at(pos + 9U));
  const size_t remainingAfterOptRRPtr = questionLen - pos - 9U;

  {
    /* smaller than the RD length */
    BOOST_CHECK_EQUAL(getEDNSOption(optRR, 1U, EDNSOptionCode::ECS, &ecsStartPosition, &ecsLen), EINVAL);
    /* smaller than the content of the RD length data */
    BOOST_CHECK_EQUAL(getEDNSOption(optRR, 2U, EDNSOptionCode::ECS, &ecsStartPosition, &ecsLen), EINVAL);
    /* last byte missing */
    BOOST_CHECK_EQUAL(getEDNSOption(optRR, remainingAfterOptRRPtr - 1U, EDNSOptionCode::ECS, &ecsStartPosition, &ecsLen), EINVAL);
  }

  int res = getEDNSOption(optRR, remainingAfterOptRRPtr, EDNSOptionCode::ECS, &ecsStartPosition, &ecsLen);
  BOOST_CHECK_EQUAL(res, 0);

  EDNSSubnetOpts eso;
  BOOST_REQUIRE(EDNSSubnetOpts::getFromString(reinterpret_cast<const char*>(&query.at(pos + 9 + ecsStartPosition + 4)), ecsLen - 4, &eso)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)

  BOOST_CHECK(eso.getSource() == ecs);

  {
    /* option length too large */
    auto copy = query;
    copy.at(pos + 9U + ecsStartPosition + 2U) += 20U;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto* optRRCopy = reinterpret_cast<const char*>(&copy.at(pos + 9U));
    BOOST_CHECK_EQUAL(getEDNSOption(optRRCopy, remainingAfterOptRRPtr, EDNSOptionCode::ECS, &ecsStartPosition, &ecsLen), EINVAL);
  }

  {
    /* trailing bytes in OPT RR */
    auto copy = query;
    /* add 1 byte to rdLen */
    copy.at(pos + 9U + 1U)++;
    /* and one byte to the buffer */
    copy.push_back(0U);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto* optRRCopy = reinterpret_cast<const char*>(&copy.at(pos + 9U));
    BOOST_CHECK_EQUAL(getEDNSOption(optRRCopy, remainingAfterOptRRPtr + 1U, EDNSOptionCode::ECS, &ecsStartPosition, &ecsLen), EINVAL);
  }
}

BOOST_AUTO_TEST_CASE(test_getEDNSOptions)
{
  DNSName name("www.powerdns.com.");
  Netmask ecs("127.0.0.1/32");
  vector<uint8_t> query;

  getRawQueryWithECSAndCookie(name, ecs, "deadbeef", "deadbeef", query);

  const dnsheader_aligned dnsHeader(query.data());
  unsigned int consumed = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DNSName dnsname = DNSName(reinterpret_cast<const char*>(query.data()), query.size(), sizeof(dnsheader), false, nullptr, nullptr, &consumed);

  size_t pos = sizeof(dnsheader) + consumed + 4;
  /* at least OPT root label (1), type (2), class (2) and ttl (4) + OPT RR rdlen (2) = 11 */
  BOOST_REQUIRE_EQUAL(ntohs(dnsHeader->arcount), 1);
  BOOST_REQUIRE(query.size() > pos + 11);
  /* OPT root label (1) followed by type (2) */
  BOOST_REQUIRE_EQUAL(query.at(pos), 0);
  BOOST_REQUIRE(query.at(pos + 2) == QType::OPT);

  EDNSOptionViewMap options;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  int res = getEDNSOptions(reinterpret_cast<char*>(query.data()) + pos + 9, query.size() - pos - 9, options);
  BOOST_REQUIRE_EQUAL(res, 0);

  /* 3 EDNS options but two of them are EDNS Cookie, so we only have two entries in the map */
  BOOST_CHECK_EQUAL(options.size(), 2U);

  auto optionsIt = options.find(EDNSOptionCode::ECS);
  BOOST_REQUIRE(optionsIt != options.end());
  BOOST_REQUIRE_EQUAL(optionsIt->second.values.size(), 1U);
  BOOST_REQUIRE(optionsIt->second.values.at(0).content != nullptr);
  BOOST_REQUIRE_GT(optionsIt->second.values.at(0).size, 0U);

  EDNSSubnetOpts eso;
  BOOST_REQUIRE(EDNSSubnetOpts::getFromString(optionsIt->second.values.at(0).content, optionsIt->second.values.at(0).size, &eso));
  BOOST_CHECK(eso.getSource() == ecs);

  optionsIt = options.find(EDNSOptionCode::COOKIE);
  BOOST_REQUIRE(optionsIt != options.end());
  BOOST_REQUIRE_EQUAL(optionsIt->second.values.size(), 2U);
  BOOST_REQUIRE(optionsIt->second.values.at(0).content != nullptr);
  BOOST_REQUIRE_GT(optionsIt->second.values.at(0).size, 0U);
  BOOST_REQUIRE(optionsIt->second.values.at(1).content != nullptr);
  BOOST_REQUIRE_GT(optionsIt->second.values.at(1).size, 0U);

  {
    // pass truncated OPT data
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto error = getEDNSOptions(reinterpret_cast<char*>(query.data()) + pos + 9, query.size() - pos - 9 - 1, options);
    BOOST_REQUIRE_EQUAL(error, EINVAL);
  }

  {
    // reduce the rdLen of the OPT record
    auto mangledQuery = query;
    uint16_t rdLen = (static_cast<unsigned char>(mangledQuery.at(pos + 9)) * 256U) + (static_cast<unsigned char>(mangledQuery.at(pos + 9 + 1)));
    rdLen--;
    mangledQuery.at(pos + 9) = rdLen / 256U;
    mangledQuery.at(pos + 9 + 1) = rdLen % 256U;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto error = getEDNSOptions(reinterpret_cast<char*>(mangledQuery.data()) + pos + 9, mangledQuery.size() - pos - 9, options);
    BOOST_REQUIRE_EQUAL(error, EINVAL);
  }

  {
    // add 2 trailing bytes at the end of the OPT data
    auto mangledQuery = query;
    uint16_t rdLen = (static_cast<unsigned char>(mangledQuery.at(pos + 9)) * 256U) + (static_cast<unsigned char>(mangledQuery.at(pos + 9 + 1)));
    rdLen += 2;
    mangledQuery.at(pos + 9) = rdLen / 256U;
    mangledQuery.at(pos + 9 + 1) = rdLen % 256U;
    PacketBuffer trailingBytes{0xFD, 0xE9};
    mangledQuery.insert(mangledQuery.end(), trailingBytes.begin(), trailingBytes.end());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto error = getEDNSOptions(reinterpret_cast<char*>(mangledQuery.data()) + pos + 9, mangledQuery.size() - pos - 9, options);
    BOOST_REQUIRE_EQUAL(error, EINVAL);
  }
}

static void checkECSOptionValidity(const std::string& sourceStr, uint8_t sourceMask, uint8_t scopeMask)
{
  ComboAddress source(sourceStr);
  EDNSSubnetOpts ecsOpts;
  ecsOpts.setSource(Netmask(source, sourceMask));

  string ecsOptionStr = ecsOpts.makeOptString();

  /* 2 bytes for family, one for source mask and one for scope mask */
  const size_t ecsHeaderSize = 4;
  uint8_t sourceBytes = ((sourceMask - 1) >> 3) + 1;
  BOOST_REQUIRE_EQUAL(ecsOptionStr.size(), (ecsHeaderSize + sourceBytes));
  /* family */
  uint16_t u;
  memcpy(&u, ecsOptionStr.c_str(), sizeof(u));
  BOOST_REQUIRE_EQUAL(ntohs(u), source.isIPv4() ? 1 : 2);
  /* source mask */
  BOOST_REQUIRE_EQUAL(static_cast<uint8_t>(ecsOptionStr.at(2)), sourceMask);
  BOOST_REQUIRE_EQUAL(static_cast<uint8_t>(ecsOptionStr.at(3)), scopeMask);
  ComboAddress truncated(source);
  truncated.truncate(sourceMask);

  if (sourceMask > 0) {
    ComboAddress res;

    if (source.isIPv4()) {
      memset(&res.sin4, 0, sizeof(res.sin4));
      res.sin4.sin_family = AF_INET;
      memcpy(&res.sin4.sin_addr.s_addr, &ecsOptionStr.at(4), sourceBytes);
      BOOST_REQUIRE(res == truncated);
    }
    else {
      memset(&res.sin6, 0, sizeof(res.sin6));
      res.sin6.sin6_family = AF_INET6;
      memcpy(&res.sin6.sin6_addr.s6_addr, &ecsOptionStr.at(4), sourceBytes);
      BOOST_REQUIRE(res == truncated);
    }
  }

  EDNSSubnetOpts parsed;
  BOOST_REQUIRE(EDNSSubnetOpts::getFromString(ecsOptionStr, &parsed));
  BOOST_REQUIRE(parsed.getSource() == Netmask(truncated, sourceMask));
  BOOST_REQUIRE_EQUAL(ecsOpts.getScopePrefixLength(), parsed.getScopePrefixLength());
}

BOOST_AUTO_TEST_CASE(test_makeEDNSSubnetOptsString)
{
  checkECSOptionValidity("192.0.2.255", 0, 0);
  checkECSOptionValidity("192.0.2.255", 8, 0);
  checkECSOptionValidity("255.255.255.255", 9, 0);
  checkECSOptionValidity("192.0.2.255", 31, 0);
  checkECSOptionValidity("192.0.2.255", 32, 0);
  checkECSOptionValidity("2001:DB8::FFFF", 0, 0);
  checkECSOptionValidity("2001:DB8::FFFF", 32, 0);
  checkECSOptionValidity("2001:DB8::FFFF", 127, 0);
  checkECSOptionValidity("2001:DB8::FFFF", 128, 0);
}

static void checkExtendedErrorOptionValidity(EDNSExtendedError::code code, const std::string& extra)
{
  EDNSExtendedError eee;
  eee.infoCode = static_cast<uint16_t>(code);
  eee.extraText = extra;

  const auto optionStr = makeEDNSExtendedErrorOptString(eee);
  BOOST_REQUIRE_EQUAL(optionStr.size(), sizeof(code) + extra.size());

  uint16_t u;
  memcpy(&u, optionStr.c_str(), sizeof(u));
  BOOST_CHECK_EQUAL(ntohs(u), static_cast<uint16_t>(code));
  BOOST_CHECK_EQUAL(optionStr.substr(2), extra);

  EDNSExtendedError parsed;
  BOOST_REQUIRE(getEDNSExtendedErrorOptFromString(optionStr, parsed));
  BOOST_CHECK_EQUAL(parsed.infoCode, static_cast<uint16_t>(code));
  BOOST_CHECK_EQUAL(parsed.extraText, extra);
}

BOOST_AUTO_TEST_CASE(test_makeEDNSExtendedErrorOptString)
{
  checkExtendedErrorOptionValidity(EDNSExtendedError::code::Other, "");
  checkExtendedErrorOptionValidity(static_cast<EDNSExtendedError::code>(255), "");

  checkExtendedErrorOptionValidity(EDNSExtendedError::code::UnsupportedDNSKEYAlgorithm, "");
  checkExtendedErrorOptionValidity(EDNSExtendedError::code::UnsupportedDSDigestType, "The digest type of this DS is not supported!");

  std::string extra;
  /* the size of an EDNS option is limited to 2^16-1, and in this case the code already adds 2 bytes */
  extra.resize(65534);
  BOOST_CHECK_THROW(checkExtendedErrorOptionValidity(EDNSExtendedError::code::Other, extra), std::runtime_error);

  EDNSExtendedError parsed;
  std::string empty;
  BOOST_CHECK(!getEDNSExtendedErrorOptFromString(empty, parsed));
}

BOOST_AUTO_TEST_CASE(test_slowParseEDNSOptions_root_opt)
{
  const DNSName qname("example.com.");
  std::vector<uint8_t> packet;
  DNSPacketWriter packetWriter(packet, qname, QType::A, QClass::IN, 0);
  packetWriter.commit();

  /* make it look like a response: one answer record */
  packetWriter.startRecord(qname, QType::A, 60, QClass::IN, DNSResourceRecord::ANSWER, true);
  packetWriter.xfr32BitInt(0x01020304U);
  packetWriter.commit();

  EDNSSubnetOpts ecsOpts;
  ecsOpts.setSource(Netmask("192.0.2.0/24"));
  const std::string ecsOption = ecsOpts.makeOptString();

  uint32_t ttl{0};
  EDNS0Record stuff{};
  stuff.version = 0;
  stuff.extFlags = htons(0);
  stuff.extRCode = 0;
  memcpy(&ttl, &stuff, sizeof(stuff));
  ttl = ntohl(ttl);
  /* OPT RR with a non-root owner name */
  packetWriter.startRecord(DNSName("."), QType::OPT, ttl, 512U, DNSResourceRecord::ADDITIONAL, false);
  packetWriter.xfr16BitInt(EDNSOptionCode::ECS);
  packetWriter.xfr16BitInt(ecsOption.length());
  packetWriter.xfrBlob(ecsOption);
  packetWriter.commit();

  PacketBuffer pbuf(packet.begin(), packet.end());
  EDNSOptionViewMap options;
  const bool parsed = slowParseEDNSOptions(pbuf, options);
  BOOST_CHECK_EQUAL(parsed, true);
  BOOST_REQUIRE(options.find(EDNSOptionCode::ECS) != options.end());
  BOOST_CHECK_EQUAL(options.at(EDNSOptionCode::ECS).values.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_slowParseEDNSOptions_non_root_opt)
{
  const DNSName qname("example.com.");
  std::vector<uint8_t> packet;
  DNSPacketWriter packetWriter(packet, qname, QType::A, QClass::IN, 0);
  packetWriter.commit();

  /* make it look like a response: one answer record */
  packetWriter.startRecord(qname, QType::A, 60, QClass::IN, DNSResourceRecord::ANSWER, true);
  packetWriter.xfr32BitInt(0x01020304U);
  packetWriter.commit();

  EDNSSubnetOpts ecsOpts;
  ecsOpts.setSource(Netmask("192.0.2.0/24"));
  const std::string ecsOption = ecsOpts.makeOptString();

  uint32_t ttl{0};
  EDNS0Record stuff{};
  stuff.version = 0;
  stuff.extFlags = htons(0);
  stuff.extRCode = 0;
  memcpy(&ttl, &stuff, sizeof(stuff));
  ttl = ntohl(ttl);
  /* OPT RR with a non-root owner name */
  packetWriter.startRecord(DNSName("evil.example."), QType::OPT, ttl, 512U, DNSResourceRecord::ADDITIONAL, false);
  packetWriter.xfr16BitInt(EDNSOptionCode::ECS);
  packetWriter.xfr16BitInt(ecsOption.length());
  packetWriter.xfrBlob(ecsOption);
  packetWriter.commit();

  PacketBuffer pbuf(packet.begin(), packet.end());
  EDNSOptionViewMap options;
  const bool parsed = slowParseEDNSOptions(pbuf, options);
  BOOST_CHECK_EQUAL(parsed, false);
  BOOST_REQUIRE(options.find(EDNSOptionCode::ECS) == options.end());
}

BOOST_AUTO_TEST_CASE(test_getEDNSOptionsFromContent)
{
  const DNSName name("www.powerdns.com.");
  {
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> writer(query, name, QType::A, QClass::IN, 0);
    writer.addOpt(512U, 0U, 0U, {{EDNSOptionCode::NSID, "test"}});
    writer.commit();

    auto content = getOPTContentFromPacket(query);
    std::vector<std::pair<uint16_t, std::string>> options;
    BOOST_CHECK(getEDNSOptionsFromContent(content, options));
    BOOST_REQUIRE_EQUAL(options.size(), 1U);
    BOOST_CHECK_EQUAL(options.at(0).first, EDNSOptionCode::NSID);
    BOOST_CHECK_EQUAL(options.at(0).second, "test");

    {
      auto truncatedContent = content.substr(0, content.size() - 1);
      options.clear();
      BOOST_CHECK(!getEDNSOptionsFromContent(truncatedContent, options));
    }

    /* add trailing bytes to the OPT RR data */
    PacketBuffer trailingBytes{0xFD, 0xE9};
    content.insert(content.end(), trailingBytes.begin(), trailingBytes.end());
    options.clear();
    BOOST_CHECK(!getEDNSOptionsFromContent(content, options));
  }
}

BOOST_AUTO_TEST_SUITE_END()
