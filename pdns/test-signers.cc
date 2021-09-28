#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>

#include <boost/tuple/tuple.hpp>

#include "base32.hh"
#include "base64.hh"
#include "dnsseckeeper.hh"
#include "dnssecinfra.hh"
#include "misc.hh"

BOOST_AUTO_TEST_SUITE(test_signers)

static const std::string message = "Very good, young padawan.";

static const struct signerParams
{
  std::string iscMap;
  std::string dsSHA1;
  std::string dsSHA256;
  std::string dsSHA384;
  std::vector<uint8_t> signature;
  std::string zoneRepresentation;
  std::string name;
  std::string rfcMsgDump;
  std::string rfcB64Signature;
  int bits;
  uint16_t flags;
  uint16_t rfcFlags;
  uint8_t algorithm;
  bool isDeterministic;
} signers[] = {
  /* RSA from https://github.com/CZ-NIC/knot/blob/master/src/dnssec/tests/sample_keys.h */
  { "Algorithm: 8\n"
    "Modulus: qtunSiHnYq4XRLBehKAw1Glxb+48oIpAC7w3Jhpj570bb2uHt6orWGqnuyRtK8oqUi2ABoV0PFm8+IPgDMEdCQ==\n"
    "PublicExponent: AQAB\n"
    "PrivateExponent: MiItniUAngXzMeaGdWgDq/AcpvlCtOCcFlVt4TJRKkfp8DNRSxIxG53NNlOFkp1W00iLHqYC2GrH1qkKgT9l+Q==\n"
    "Prime1: 3sZmM+5FKFy5xaRt0n2ZQOZ2C+CoKzVil6/al9LmYVs=\n"
    "Prime2: xFcNWSIW6v8dDL2JQ1kxFDm/8RVeUSs1BNXXnvCjBGs=\n"
    "Exponent1: WuUwhjfN1+4djlrMxHmisixWNfpwI1Eg7Ss/UXsnrMk=\n"
    "Exponent2: vfMqas1cNsXRqP3Fym6D2Pl2BRuTQBv5E1B/ZrmQPTk=\n"
    "Coefficient: Q10z43cA3hkwOkKsj5T0W5jrX97LBwZoY5lIjDCa4+M=\n",
    "1506 8 1 172a500b374158d1a64ba3073cdbbc319b2fdf2c",
    "1506 8 2 253b099ff47b02c6ffa52695a30a94c6681c56befe0e71a5077d6f79514972f9",
    "1506 8 4 22ea940600dc2d9a98b1126c26ac0dc5c91b31eb50fe784b36ad675e9eecfe6573c1f85c53b6bc94580f3ac443d13c4c",
    /* from https://github.com/CZ-NIC/knot/blob/master/src/dnssec/tests/sign.c */
    { 0x93, 0x93, 0x5f, 0xd8, 0xa1, 0x2b, 0x4c, 0x0b, 0xf3, 0x67, 0x42, 0x13, 0x52, 0x00, 0x35, 0xdc, 0x09, 0xe0, 0xdf, 0xe0, 0x3e, 0xc2, 0xcf, 0x64, 0xab, 0x9f, 0x9f, 0x51, 0x5f, 0x5c, 0x27, 0xbe, 0x13, 0xd6, 0x17, 0x07, 0xa6, 0xe4, 0x3b, 0x63, 0x44, 0x85, 0x06, 0x13, 0xaa, 0x01, 0x3c, 0x58, 0x52, 0xa3, 0x98, 0x20, 0x65, 0x03, 0xd0, 0x40, 0xc8, 0xa0, 0xe9, 0xd2, 0xc0, 0x03, 0x5a, 0xab },
    "256 3 8 AwEAAarbp0oh52KuF0SwXoSgMNRpcW/uPKCKQAu8NyYaY+e9G29rh7eqK1hqp7skbSvKKlItgAaFdDxZvPiD4AzBHQk=",
    "rsa.",
    "",
    "",
    512,
    256,
    0,
    DNSSECKeeper::RSASHA256,
    true
  },
#ifdef HAVE_LIBCRYPTO_ECDSA
  /* ECDSA-P256-SHA256 from https://github.com/CZ-NIC/knot/blob/master/src/dnssec/tests/sample_keys.h */
  { "Algorithm: 13\n"
    "PrivateKey: iyLIPdk3DOIxVmmSYlmTstbtUPiVlEyDX46psyCwNVQ=\n",
    "5345 13 1 954103ac7c43810ce9f414e80f30ab1cbe49b236",
    "5345 13 2 bac2107036e735b50f85006ce409a19a3438cab272e70769ebda032239a3d0ca",
    "5345 13 4 a0ac6790483872be72a258314200a88ab75cdd70f66a18a09f0f414c074df0989fdb1df0e67d82d4312cda67b93a76c1",
    /* from https://github.com/CZ-NIC/knot/blob/master/src/dnssec/tests/sign.c */
    { 0xa2, 0x95, 0x76, 0xb5, 0xf5, 0x7e, 0xbd, 0xdd, 0xf5, 0x62, 0xa2, 0xc3, 0xa4, 0x8d, 0xd4, 0x53, 0x5c, 0xba, 0x29, 0x71,	0x8c, 0xcc, 0x28, 0x7b, 0x58, 0xf3, 0x1e, 0x4e, 0x58, 0xe2, 0x36, 0x7e,	0xa0, 0x1a, 0xb6, 0xe6, 0x29, 0x71, 0x1b, 0xd3, 0x8c, 0x88, 0xc3, 0xee, 0x12, 0x0e, 0x69, 0x70, 0x55, 0x99, 0xec, 0xd5,	0xf6, 0x4f, 0x4b, 0xe2, 0x41, 0xd9, 0x10, 0x7e, 0x67, 0xe5, 0xad, 0x2f, },
    "256 3 13 8uD7C4THTM/w7uhryRSToeE/jKT78/p853RX0L5EwrZrSLBubLPiBw7gbvUP6SsIga5ZQ4CSAxNmYA/gZsuXzA==",
    "ecdsa.",
    "",
    "",
    256,
    256,
    0,
    DNSSECKeeper::ECDSA256,
    false
  },
#endif /* HAVE_LIBCRYPTO_ECDSA */
#if defined(HAVE_LIBSODIUM) || defined(HAVE_LIBCRYPTO_ED25519)
  /* ed25519 from https://github.com/CZ-NIC/knot/blob/master/src/dnssec/tests/sample_keys.h,
     also from rfc8080 section 6.1 */
  { "Algorithm: 15\n"
    "PrivateKey: ODIyNjAzODQ2MjgwODAxMjI2NDUxOTAyMDQxNDIyNjI=\n",
    "3612 15 1 501249721e1f09a79d30d5c6c4dca1dc1da4ed5d",
    "3612 15 2 1b1c8766b2a96566ff196f77c0c4194af86aaa109c5346ff60231a27d2b07ac0",
    "3612 15 4 d11831153af4985efbd0ae792c967eb4aff3c35488db95f7e2f85dcec74ae8f59f9a72641798c91c67c675db1d710c18",
    /* from https://github.com/CZ-NIC/knot/blob/master/src/dnssec/tests/sign.c */
    { 0x0a, 0x9e, 0x51, 0x5f, 0x16, 0x89, 0x49, 0x27, 0x0e, 0x98, 0x34, 0xd3, 0x48, 0xef, 0x5a, 0x6e, 0x85, 0x2f, 0x7c, 0xd6, 0xd7, 0xc8, 0xd0, 0xf4, 0x2c, 0x68, 0x8c, 0x1f, 0xf7, 0xdf, 0xeb, 0x7c, 0x25, 0xd6, 0x1a, 0x76, 0x3e, 0xaf, 0x28, 0x1f, 0x1d, 0x08, 0x10, 0x20, 0x1c, 0x01, 0x77, 0x1b, 0x5a, 0x48, 0xd6, 0xe5, 0x1c, 0xf9, 0xe3, 0xe0, 0x70, 0x34, 0x5e, 0x02, 0x49, 0xfb, 0x9e, 0x05 },
    "256 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=",
    "ed25519.",
    // vector extracted from https://gitlab.labs.nic.cz/labs/ietf/blob/master/dnskey.py (rev 476d6ded) by printing signature_data
    "00 0f 0f 02 00 00 0e 10 55 d4 fc 60 55 b9 4c e0 0e 1d 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 0f 00 01 00 00 0e 10 00 14 00 0a 04 6d 61 69 6c 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ",
    // vector verified from dnskey.py as above, and confirmed with https://www.rfc-editor.org/errata_search.php?rfc=8080&eid=4935
    "oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3fx8A4M3e23mRZ9VrbpMngwcrqNAg==",
    256,
    256,
    257,
    DNSSECKeeper::ED25519,
    true
  },
#endif /* defined(HAVE_LIBSODIUM) || defined(HAVE_LIBCRYPTO_ED25519) */
};

static void checkRR(const signerParams& signer)
{
  DNSKEYRecordContent drc;
  auto dcke = std::shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::makeFromISCString(drc, signer.iscMap));
  DNSSECPrivateKey dpk;
  dpk.setKey(dcke);
  dpk.d_flags = signer.rfcFlags;

  sortedRecords_t rrs;
  /* values taken from rfc8080 for ed25519 and ed448, rfc5933 for gost */
  DNSName qname(dpk.d_algorithm == 12 ? "www.example.net." : "example.com.");

  reportBasicTypes();

  RRSIGRecordContent rrc;
  uint32_t expire = 1440021600;
  uint32_t inception = 1438207200;

  if (dpk.d_algorithm == 12) {
    rrc.d_signer = DNSName("example.net.");
    inception = 946684800;
    expire = 1893456000;
    rrs.insert(DNSRecordContent::mastermake(QType::A, QClass::IN, "192.0.2.1"));
  }
  else {
    rrc.d_signer = qname;
    rrs.insert(DNSRecordContent::mastermake(QType::MX, QClass::IN, "10 mail.example.com."));
  }

  rrc.d_originalttl = 3600;
  rrc.d_sigexpire = expire;
  rrc.d_siginception = inception;
  rrc.d_type = (*rrs.cbegin())->getType();
  rrc.d_labels = qname.countLabels();
  rrc.d_tag = dpk.getTag();
  rrc.d_algorithm = dpk.d_algorithm;

  string msg = getMessageForRRSET(qname, rrc, rrs, false);

  BOOST_CHECK_EQUAL(makeHexDump(msg), signer.rfcMsgDump);

  string signature = dcke->sign(msg);

  BOOST_CHECK(dcke->verify(msg, signature));

  if (signer.isDeterministic) {
    string b64 = Base64Encode(signature);
    BOOST_CHECK_EQUAL(b64, signer.rfcB64Signature);
  }
  else {
    std::string raw;
    B64Decode(signer.rfcB64Signature, raw);
    BOOST_CHECK(dcke->verify(msg, raw));
  }
}

BOOST_AUTO_TEST_CASE(test_generic_signers)
{
  for (const auto& signer : signers) {
    DNSKEYRecordContent drc;
    auto dcke = std::shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::makeFromISCString(drc, signer.iscMap));

    BOOST_CHECK_EQUAL(dcke->getAlgorithm(), signer.algorithm);
    BOOST_CHECK_EQUAL(dcke->getBits(), signer.bits);
    BOOST_CHECK_EQUAL(dcke->checkKey(nullptr), true);

    BOOST_CHECK_EQUAL(drc.d_algorithm, signer.algorithm);

    DNSSECPrivateKey dpk;
    dpk.setKey(dcke);
    dpk.d_flags = signer.flags;
    drc = dpk.getDNSKEY();

    BOOST_CHECK_EQUAL(drc.d_algorithm, signer.algorithm);
    BOOST_CHECK_EQUAL(drc.d_protocol, 3);
    BOOST_CHECK_EQUAL(drc.getZoneRepresentation(), signer.zoneRepresentation);

    DNSName name(signer.name);
    auto ds1 = makeDSFromDNSKey(name, drc, DNSSECKeeper::DIGEST_SHA1);
    if (!signer.dsSHA1.empty()) {
      BOOST_CHECK_EQUAL(ds1.getZoneRepresentation(), signer.dsSHA1);
    }

    auto ds2 = makeDSFromDNSKey(name, drc, DNSSECKeeper::DIGEST_SHA256);
    if (!signer.dsSHA256.empty()) {
      BOOST_CHECK_EQUAL(ds2.getZoneRepresentation(), signer.dsSHA256);
    }

    auto ds4 = makeDSFromDNSKey(name, drc, DNSSECKeeper::DIGEST_SHA384);
    if (!signer.dsSHA384.empty()) {
      BOOST_CHECK_EQUAL(ds4.getZoneRepresentation(), signer.dsSHA384);
    }

    auto signature = dcke->sign(message);
    BOOST_CHECK(dcke->verify(message, signature));

    if (signer.isDeterministic) {
      BOOST_CHECK_EQUAL(signature, std::string(signer.signature.begin(), signer.signature.end()));
    } else {
      /* since the signing process is not deterministic, we can't directly compare our signature
         with the one we have. Still the one we have should also validate correctly. */
      BOOST_CHECK(dcke->verify(message, std::string(signer.signature.begin(), signer.signature.end())));
    }

    if (!signer.rfcMsgDump.empty() && !signer.rfcB64Signature.empty()) {
      checkRR(signer);
    }
  }
}

#if defined(HAVE_LIBCRYPTO_ED448)
BOOST_AUTO_TEST_CASE(test_ed448_signer) {
    sortedRecords_t rrs;
    DNSName qname("example.com.");
    DNSKEYRecordContent drc;

    // TODO: make this a collection of inputs and resulting sigs for various algos
    shared_ptr<DNSCryptoKeyEngine> engine = DNSCryptoKeyEngine::makeFromISCString(drc,
"Private-key-format: v1.2\n"
"Algorithm: 16 (ED448)\n"
"PrivateKey: xZ+5Cgm463xugtkY5B0Jx6erFTXp13rYegst0qRtNsOYnaVpMx0Z/c5EiA9x8wWbDDct/U3FhYWA\n");

    DNSSECPrivateKey dpk;
    dpk.setKey(engine);

    reportBasicTypes();

    rrs.insert(DNSRecordContent::mastermake(QType::MX, 1, "10 mail.example.com."));

    RRSIGRecordContent rrc;
    rrc.d_originalttl = 3600;
    rrc.d_sigexpire = 1440021600;
    rrc.d_siginception = 1438207200;
    rrc.d_signer = qname;
    rrc.d_type = QType::MX;
    rrc.d_labels = 2;
    // TODO: derive the next two from the key
    rrc.d_tag = 9713;
    rrc.d_algorithm = 16;

    string msg = getMessageForRRSET(qname, rrc, rrs, false);

    // vector extracted from https://gitlab.labs.nic.cz/labs/ietf/blob/master/dnskey.py (rev 476d6ded) by printing signature_data
    BOOST_CHECK_EQUAL(makeHexDump(msg), "00 0f 10 02 00 00 0e 10 55 d4 fc 60 55 b9 4c e0 25 f1 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 0f 00 01 00 00 0e 10 00 14 00 0a 04 6d 61 69 6c 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ");

    string signature = engine->sign(msg);
    string b64 = Base64Encode(signature);

    // vector verified from dnskey.py as above, and confirmed with https://www.rfc-editor.org/errata_search.php?rfc=8080&eid=4935
    BOOST_CHECK_EQUAL(b64, "3cPAHkmlnxcDHMyg7vFC34l0blBhuG1qpwLmjInI8w1CMB29FkEAIJUA0amxWndkmnBZ6SKiwZSAxGILn/NBtOXft0+Gj7FSvOKxE/07+4RQvE581N3Aj/JtIyaiYVdnYtyMWbSNyGEY2213WKsJlwEA");
}
#endif /* defined(HAVE_LIBCRYPTO_ED448) */

BOOST_AUTO_TEST_CASE(test_hash_qname_with_salt) {
  {
    // rfc5155 appendix A
    const unsigned char salt[] = { 0xaa, 0xbb, 0xcc, 0xdd };
    const unsigned int iterations{12};
    const std::vector<std::pair<std::string, std::string>> namesToHashes = {
      { "example", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom" },
      { "a.example", "35mthgpgcu1qg68fab165klnsnk3dpvl" },
      { "ai.example", "gjeqe526plbf1g8mklp59enfd789njgi" },
      { "ns1.example", "2t7b4g4vsa5smi47k61mv5bv1a22bojr" },
      { "ns2.example", "q04jkcevqvmu85r014c7dkba38o0ji5r" },
      { "w.example", "k8udemvp1j2f7eg6jebps17vp3n8i58h" },
      { "*.w.example", "r53bq7cc2uvmubfu5ocmm6pers9tk9en" },
      { "x.w.example", "b4um86eghhds6nea196smvmlo4ors995" },
      { "y.w.example", "ji6neoaepv8b5o6k4ev33abha8ht9fgc" },
      { "x.y.w.example", "2vptu5timamqttgl4luu9kg21e0aor3s" },
      { "xx.example", "t644ebqk9bibcna874givr6joj62mlhv" },
      { "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example", "kohar7mbb8dc2ce8a9qvl8hon4k53uhi" },
    };

    for (const auto& [name, expectedHash] : namesToHashes) {
      auto hash = hashQNameWithSalt(std::string(reinterpret_cast<const char*>(salt), sizeof(salt)), iterations, DNSName(name));
      BOOST_CHECK_EQUAL(toBase32Hex(hash), expectedHash);
    }
  }

  {
    /* no additional iterations, very short salt */
    const unsigned char salt[] = { 0xFF };
    const unsigned int iterations{0};
    const std::vector<std::pair<std::string, std::string>> namesToHashes = {
      { "example", "s9dp8o2l6jgqgg26ecobtjooe7p019cs" },
    };

    for (const auto& [name, expectedHash] : namesToHashes) {
      auto hash = hashQNameWithSalt(std::string(reinterpret_cast<const char*>(salt), sizeof(salt)), iterations, DNSName(name));
      BOOST_CHECK_EQUAL(toBase32Hex(hash), expectedHash);
    }
  }

  {
    /* only one iteration */
    const unsigned char salt[] = { 0xaa, 0xbb, 0xcc, 0xdd };
    const unsigned int iterations{1};
    const std::vector<std::pair<std::string, std::string>> namesToHashes = {
      { "example", "ulddquehrj5jpf50ga76vgqr1oq40133" },
    };

    for (const auto& [name, expectedHash] : namesToHashes) {
      auto hash = hashQNameWithSalt(std::string(reinterpret_cast<const char*>(salt), sizeof(salt)), iterations, DNSName(name));
      BOOST_CHECK_EQUAL(toBase32Hex(hash), expectedHash);
    }
  }

  {
    /* 65535 iterations, long salt */
    unsigned char salt[255];
    for (unsigned char idx = 0; idx < 255; idx++) {
      salt[idx] = idx;
    };
    const unsigned int iterations{65535};
    const std::vector<std::pair<std::string, std::string>> namesToHashes = {
      { "example", "no95j4cfile8avstr7bn4aj9he18trri" },
    };

    for (const auto& [name, expectedHash] : namesToHashes) {
      auto hash = hashQNameWithSalt(std::string(reinterpret_cast<const char*>(salt), sizeof(salt)), iterations, DNSName(name));
      BOOST_CHECK_EQUAL(toBase32Hex(hash), expectedHash);
    }
  }
}

BOOST_AUTO_TEST_SUITE_END()
