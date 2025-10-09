#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>

#include "base32.hh"
#include "base64.hh"
#include "dnssec.hh"
#include "dnssecinfra.hh"
#include "misc.hh"

// Include below is essential, otherwise we get failures I do not understand, maybe some runtime
// value does not get initialized?
#include <openssl/sha.h>

#include <unordered_map>

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): Boost stuff.
BOOST_AUTO_TEST_SUITE(test_signers)

struct SignerParams
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
  std::string pem;
};

// clang-format off
static const SignerParams rsaSha256SignerParams = SignerParams
{
  .iscMap = "Algorithm: 8\n"
            "Modulus: qtunSiHnYq4XRLBehKAw1Glxb+48oIpAC7w3Jhpj570bb2uHt6orWGqnuyRtK8oqUi2ABoV0PFm8+IPgDMEdCQ==\n"
            "PublicExponent: AQAB\n"
            "PrivateExponent: MiItniUAngXzMeaGdWgDq/AcpvlCtOCcFlVt4TJRKkfp8DNRSxIxG53NNlOFkp1W00iLHqYC2GrH1qkKgT9l+Q==\n"
            "Prime1: 3sZmM+5FKFy5xaRt0n2ZQOZ2C+CoKzVil6/al9LmYVs=\n"
            "Prime2: xFcNWSIW6v8dDL2JQ1kxFDm/8RVeUSs1BNXXnvCjBGs=\n"
            "Exponent1: WuUwhjfN1+4djlrMxHmisixWNfpwI1Eg7Ss/UXsnrMk=\n"
            "Exponent2: vfMqas1cNsXRqP3Fym6D2Pl2BRuTQBv5E1B/ZrmQPTk=\n"
            "Coefficient: Q10z43cA3hkwOkKsj5T0W5jrX97LBwZoY5lIjDCa4+M=\n",

  .dsSHA1 = "1506 8 1 "
            "172a500b374158d1a64ba3073cdbbc319b2fdf2c",

  .dsSHA256 = "1506 8 2 "
              "253b099ff47b02c6ffa52695a30a94c6681c56befe0e71a5077d6f79514972f9",

  .dsSHA384 = "1506 8 4 "
              "22ea940600dc2d9a98b1126c26ac0dc5c91b31eb50fe784b"
              "36ad675e9eecfe6573c1f85c53b6bc94580f3ac443d13c4c",

  /* from https://github.com/CZ-NIC/knot/blob/master/src/dnssec/tests/sign.c */
  .signature = {
    0x93, 0x93, 0x5f, 0xd8, 0xa1, 0x2b, 0x4c, 0x0b, 0xf3, 0x67, 0x42, 0x13, 0x52,
    0x00, 0x35, 0xdc, 0x09, 0xe0, 0xdf, 0xe0, 0x3e, 0xc2, 0xcf, 0x64, 0xab, 0x9f,
    0x9f, 0x51, 0x5f, 0x5c, 0x27, 0xbe, 0x13, 0xd6, 0x17, 0x07, 0xa6, 0xe4, 0x3b,
    0x63, 0x44, 0x85, 0x06, 0x13, 0xaa, 0x01, 0x3c, 0x58, 0x52, 0xa3, 0x98, 0x20,
    0x65, 0x03, 0xd0, 0x40, 0xc8, 0xa0, 0xe9, 0xd2, 0xc0, 0x03, 0x5a, 0xab
  },

  .zoneRepresentation = "256 3 8 "
                        "AwEAAarbp0oh52KuF0SwXoSgMNRpcW/uPKCKQAu8NyYaY+"
                        "e9G29rh7eqK1hqp7skbSvKKlItgAaFdDxZvPiD4AzBHQk=",

  .name = "rsa.",

  .rfcMsgDump = "",
  .rfcB64Signature = "",

  .bits = 512,
  .flags = 256,
  .rfcFlags = 0,

  .algorithm = DNSSEC::RSASHA256,
  .isDeterministic = true,

#if OPENSSL_VERSION_MAJOR >= 3
  // OpenSSL 3.0.0 uses a generic key interface which stores the key PKCS#8-encoded.
  .pem = "-----BEGIN PRIVATE KEY-----\n"
         "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAqtunSiHnYq4XRLBe\n"
         "hKAw1Glxb+48oIpAC7w3Jhpj570bb2uHt6orWGqnuyRtK8oqUi2ABoV0PFm8+IPg\n"
         "DMEdCQIDAQABAkAyIi2eJQCeBfMx5oZ1aAOr8Bym+UK04JwWVW3hMlEqR+nwM1FL\n"
         "EjEbnc02U4WSnVbTSIsepgLYasfWqQqBP2X5AiEA3sZmM+5FKFy5xaRt0n2ZQOZ2\n"
         "C+CoKzVil6/al9LmYVsCIQDEVw1ZIhbq/x0MvYlDWTEUOb/xFV5RKzUE1dee8KME\n"
         "awIgWuUwhjfN1+4djlrMxHmisixWNfpwI1Eg7Ss/UXsnrMkCIQC98ypqzVw2xdGo\n"
         "/cXKboPY+XYFG5NAG/kTUH9muZA9OQIgQ10z43cA3hkwOkKsj5T0W5jrX97LBwZo\n"
         "Y5lIjDCa4+M=\n"
         "-----END PRIVATE KEY-----\n"
#else
  .pem = "-----BEGIN RSA PRIVATE KEY-----\n"
         "MIIBOgIBAAJBAKrbp0oh52KuF0SwXoSgMNRpcW/uPKCKQAu8NyYaY+e9G29rh7eq\n"
         "K1hqp7skbSvKKlItgAaFdDxZvPiD4AzBHQkCAwEAAQJAMiItniUAngXzMeaGdWgD\n"
         "q/AcpvlCtOCcFlVt4TJRKkfp8DNRSxIxG53NNlOFkp1W00iLHqYC2GrH1qkKgT9l\n"
         "+QIhAN7GZjPuRShcucWkbdJ9mUDmdgvgqCs1Ypev2pfS5mFbAiEAxFcNWSIW6v8d\n"
         "DL2JQ1kxFDm/8RVeUSs1BNXXnvCjBGsCIFrlMIY3zdfuHY5azMR5orIsVjX6cCNR\n"
         "IO0rP1F7J6zJAiEAvfMqas1cNsXRqP3Fym6D2Pl2BRuTQBv5E1B/ZrmQPTkCIENd\n"
         "M+N3AN4ZMDpCrI+U9FuY61/eywcGaGOZSIwwmuPj\n"
         "-----END RSA PRIVATE KEY-----\n"
#endif
};
// clang-format on

/* ECDSA-P256-SHA256 from
 * https://github.com/CZ-NIC/knot/blob/master/src/dnssec/tests/sample_keys.h
 */
// clang-format off
static const SignerParams ecdsaSha256 = SignerParams
{
  .iscMap = "Algorithm: 13\n"
            "PrivateKey: iyLIPdk3DOIxVmmSYlmTstbtUPiVlEyDX46psyCwNVQ=\n",

  .dsSHA1 = "5345 13 1 "
            "954103ac7c43810ce9f414e80f30ab1cbe49b236",

  .dsSHA256 = "5345 13 2 "
              "bac2107036e735b50f85006ce409a19a3438cab272e70769ebda032239a3d0ca",

  .dsSHA384 = "5345 13 4 "
              "a0ac6790483872be72a258314200a88ab75cdd70f66a18a0"
              "9f0f414c074df0989fdb1df0e67d82d4312cda67b93a76c1",

  /* from https://github.com/CZ-NIC/knot/blob/master/src/dnssec/tests/sign.c */
  .signature = {
    0xa2, 0x95, 0x76, 0xb5, 0xf5, 0x7e, 0xbd, 0xdd, 0xf5, 0x62, 0xa2, 0xc3, 0xa4,
    0x8d, 0xd4, 0x53, 0x5c, 0xba, 0x29, 0x71, 0x8c, 0xcc, 0x28, 0x7b, 0x58, 0xf3,
    0x1e, 0x4e, 0x58, 0xe2, 0x36, 0x7e, 0xa0, 0x1a, 0xb6, 0xe6, 0x29, 0x71, 0x1b,
    0xd3, 0x8c, 0x88, 0xc3, 0xee, 0x12, 0x0e, 0x69, 0x70, 0x55, 0x99, 0xec, 0xd5,
    0xf6, 0x4f, 0x4b, 0xe2, 0x41, 0xd9, 0x10, 0x7e, 0x67, 0xe5, 0xad, 0x2f
  },

  .zoneRepresentation = "256 3 13 "
                        "8uD7C4THTM/w7uhryRSToeE/jKT78/p853RX0L5EwrZ"
                        "rSLBubLPiBw7gbvUP6SsIga5ZQ4CSAxNmYA/gZsuXzA==",

  .name = "ecdsa.",

  .rfcMsgDump = "",
  .rfcB64Signature = "",

  .bits = 256,
  .flags = 256,
  .rfcFlags = 0,

  .algorithm = DNSSEC::ECDSA256,
  .isDeterministic = false,

#if OPENSSL_VERSION_MAJOR >= 3
  // OpenSSL 3.0.0 uses a generic key interface which stores the key PKCS#8-encoded.
  .pem = "-----BEGIN PRIVATE KEY-----\n"
         "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiyLIPdk3DOIxVmmS\n"
         "YlmTstbtUPiVlEyDX46psyCwNVShRANCAATy4PsLhMdMz/Du6GvJFJOh4T+MpPvz\n"
         "+nzndFfQvkTCtmtIsG5ss+IHDuBu9Q/pKwiBrllDgJIDE2ZgD+Bmy5fM\n"
         "-----END PRIVATE KEY-----\n"
#else
  .pem = "-----BEGIN EC PRIVATE KEY-----\n"
         "MHcCAQEEIIsiyD3ZNwziMVZpkmJZk7LW7VD4lZRMg1+OqbMgsDVUoAoGCCqGSM49\n"
         "AwEHoUQDQgAE8uD7C4THTM/w7uhryRSToeE/jKT78/p853RX0L5EwrZrSLBubLPi\n"
         "Bw7gbvUP6SsIga5ZQ4CSAxNmYA/gZsuXzA==\n"
         "-----END EC PRIVATE KEY-----\n"
#endif
};
// clang-format on

/* Ed25519 from https://github.com/CZ-NIC/knot/blob/master/src/dnssec/tests/sample_keys.h,
 * also from rfc8080 section 6.1
 */
// clang-format off
static const SignerParams ed25519 = SignerParams{
  .iscMap = "Algorithm: 15\n"
            "PrivateKey: ODIyNjAzODQ2MjgwODAxMjI2NDUxOTAyMDQxNDIyNjI=\n",

  .dsSHA1 = "3612 15 1 "
            "501249721e1f09a79d30d5c6c4dca1dc1da4ed5d",

  .dsSHA256 = "3612 15 2 "
              "1b1c8766b2a96566ff196f77c0c4194af86aaa109c5346ff60231a27d2b07ac0",

  .dsSHA384 = "3612 15 4 "
              "d11831153af4985efbd0ae792c967eb4aff3c35488db95f7"
              "e2f85dcec74ae8f59f9a72641798c91c67c675db1d710c18",

  /* from https://github.com/CZ-NIC/knot/blob/master/src/dnssec/tests/sign.c */
  .signature = {
    0x0a, 0x9e, 0x51, 0x5f, 0x16, 0x89, 0x49, 0x27, 0x0e, 0x98, 0x34, 0xd3, 0x48,
    0xef, 0x5a, 0x6e, 0x85, 0x2f, 0x7c, 0xd6, 0xd7, 0xc8, 0xd0, 0xf4, 0x2c, 0x68,
    0x8c, 0x1f, 0xf7, 0xdf, 0xeb, 0x7c, 0x25, 0xd6, 0x1a, 0x76, 0x3e, 0xaf, 0x28,
    0x1f, 0x1d, 0x08, 0x10, 0x20, 0x1c, 0x01, 0x77, 0x1b, 0x5a, 0x48, 0xd6, 0xe5,
    0x1c, 0xf9, 0xe3, 0xe0, 0x70, 0x34, 0x5e, 0x02, 0x49, 0xfb, 0x9e, 0x05
  },

  .zoneRepresentation = "256 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=",

  .name = "ed25519.",

  // vector extracted from https://gitlab.labs.nic.cz/labs/ietf/blob/master/dnskey.py (rev
  // 476d6ded) by printing signature_data
  .rfcMsgDump = "00 0f 0f 02 00 00 0e 10 55 d4 fc 60 55 b9 4c e0 0e 1d 07 65 78 "
                "61 6d 70 6c 65 03 63 6f 6d 00 07 65 78 61 6d 70 6c 65 03 63 6f "
                "6d 00 00 0f 00 01 00 00 0e 10 00 14 00 0a 04 6d 61 69 6c 07 65 "
                "78 61 6d 70 6c 65 03 63 6f 6d 00 ",

  // vector verified from dnskey.py as above, and confirmed with
  // https://www.rfc-editor.org/errata_search.php?rfc=8080&eid=4935
  .rfcB64Signature = "oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeR"
                     "AvTdszaPD+QLs3fx8A4M3e23mRZ9VrbpMngwcrqNAg==",

  .bits = 256,
  .flags = 256,
  .rfcFlags = 257,

  .algorithm = DNSSEC::ED25519,
  .isDeterministic = true,

  .pem = "-----BEGIN PRIVATE KEY-----\n"
         "MC4CAQAwBQYDK2VwBCIEIDgyMjYwMzg0NjI4MDgwMTIyNjQ1MTkwMjA0MTQyMjYy\n"
         "-----END PRIVATE KEY-----\n"
};
// clang-format on

/* Ed448.
 */
// clang-format off
static const SignerParams ed448 = SignerParams{
  .iscMap = "Private-key-format: v1.2\n"
            "Algorithm: 16 (ED448)\n"
            "PrivateKey: xZ+5Cgm463xugtkY5B0Jx6erFTXp13rYegst0qRtNsOYnaVpMx0Z/c5EiA9x8wWbDDct/U3FhYWA\n",

  .dsSHA1 = "9712 16 1 "
            "2873e800eb2d784cdd1802f884b3c540b573eaa0",

  .dsSHA256 = "9712 16 2 "
              "9aa27306f8a04a0a6fae8affd65d6f35875dcb134c05bd7c7b61bd0dc44009cd",

  .dsSHA384 = "9712 16 4 "
              "3876e5d892d3f31725f9964a332f9b9afd791171833480f2"
              "e71af78efb985cde9900ba95315287123a5908ca8f334369",

  .signature = {
    0xb5, 0xcc, 0x21, 0x5a, 0x52, 0x21, 0x60, 0xa3, 0xb8, 0xd9, 0x3a, 0xd7, 0x05,
    0xdd, 0x4a, 0x32, 0x96, 0xce, 0x08, 0xde, 0x74, 0x5f, 0xdb, 0xde, 0x54, 0x95,
    0x97, 0x93, 0x6f, 0x3a, 0x4a, 0x34, 0x41, 0x14, 0xba, 0x99, 0x86, 0x0d, 0xe2,
    0x99, 0xf1, 0x14, 0x6a, 0x1b, 0x7a, 0xfa, 0xef, 0xab, 0x62, 0xd2, 0x71, 0x85,
    0xae, 0xd1, 0x84, 0x80, 0x00, 0x50, 0x03, 0x9e, 0x73, 0x53, 0xe8, 0x9e, 0x19,
    0xb8, 0xc0, 0xdb, 0xd4, 0xf0, 0x1e, 0x44, 0x4c, 0xb7, 0x32, 0x07, 0xda, 0x0b,
    0x64, 0x22, 0xa8, 0x63, 0xaa, 0x7a, 0x12, 0x73, 0xc9, 0x29, 0xfd, 0x50, 0x85,
    0x0f, 0x43, 0x72, 0x77, 0x86, 0xec, 0x88, 0x1a, 0x96, 0x95, 0x4a, 0x01, 0xfe,
    0xf2, 0xe6, 0x77, 0x4a, 0x2e, 0x43, 0xdd, 0x60, 0x29, 0x00,
  },

  .zoneRepresentation = "256 3 16 "
                        "3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+"
                        "G2MpTPhpj/OiBVHHSfPodx1FYYUcJKm1MDpJtIA",

  .name = "ed448.",

  // vector extracted from https://gitlab.labs.nic.cz/labs/ietf/blob/master/dnskey.py (rev
  // 476d6ded) by printing signature_data
  .rfcMsgDump = "00 0f 10 02 00 00 0e 10 55 d4 fc 60 55 b9 4c e0 25 f1 07 65 78 "
                "61 6d 70 6c 65 03 63 6f 6d 00 07 65 78 61 6d 70 6c 65 03 63 6f "
                "6d 00 00 0f 00 01 00 00 0e 10 00 14 00 0a 04 6d 61 69 6c 07 65 "
                "78 61 6d 70 6c 65 03 63 6f 6d 00 ",

  // vector verified from dnskey.py as above, and confirmed with
  // https://www.rfc-editor.org/errata_search.php?rfc=8080&eid=4935
  .rfcB64Signature = "3cPAHkmlnxcDHMyg7vFC34l0blBhuG1qpwLmjInI8w1CMB29FkEA"
                     "IJUA0amxWndkmnBZ6SKiwZSAxGILn/NBtOXft0+Gj7FSvOKxE/07"
                     "+4RQvE581N3Aj/JtIyaiYVdnYtyMWbSNyGEY2213WKsJlwEA",

  .bits = 456,
  .flags = 256,
  .rfcFlags = 257,

  .algorithm = DNSSEC::ED448,
  .isDeterministic = true,

  .pem = "-----BEGIN PRIVATE KEY-----\n"
         "MEcCAQAwBQYDK2VxBDsEOcWfuQoJuOt8boLZGOQdCcenqxU16dd62HoLLdKkbTbD\n"
         "mJ2laTMdGf3ORIgPcfMFmww3Lf1NxYWFgA==\n"
         "-----END PRIVATE KEY-----\n"
};
// clang-format on

struct Fixture
{
  Fixture()
  {
    BOOST_TEST_MESSAGE("All available/supported algorithms:");
    auto pairs = DNSCryptoKeyEngine::listAllAlgosWithBackend();
    for (auto const& pair : pairs) {
      BOOST_TEST_MESSAGE("  " + std::to_string(pair.first) + ": " + pair.second);
    }

    BOOST_TEST_MESSAGE("Setting up signer params:");

    addSignerParams(DNSSEC::RSASHA256, "RSA SHA256", rsaSha256SignerParams);

#ifdef HAVE_LIBCRYPTO_ECDSA
    addSignerParams(DNSSEC::ECDSA256, "ECDSA SHA256", ecdsaSha256);
#endif

// We need to have HAVE_LIBCRYPTO_ED25519 for the PEM reader/writer.
#if defined(HAVE_LIBCRYPTO_ED25519)
    addSignerParams(DNSSEC::ED25519, "ED25519", ed25519);
#endif

#if defined(HAVE_LIBCRYPTO_ED448)
    addSignerParams(DNSSEC::ED448, "ED448", ed448);
#endif
  }

  void addSignerParams(const uint8_t algorithm, const std::string& name, const SignerParams& params)
  {
    BOOST_TEST_MESSAGE("  " + std::to_string(algorithm) + ": " + name + " (" + params.name + ")");
    signerParams.insert_or_assign(algorithm, params);
  }

  const std::string message{"Very good, young padawan."};
  std::unordered_map<uint8_t, struct SignerParams> signerParams;
};

static void checkRR(const SignerParams& signer)
{
  DNSKEYRecordContent drc;
  auto dcke = std::shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::makeFromISCString(drc, signer.iscMap));
  DNSSECPrivateKey dpk;
  dpk.setKey(dcke, signer.rfcFlags);

  sortedRecords_t rrs;
  /* values taken from rfc8080 for ed25519 and ed448, rfc5933 for gost */
  DNSName qname(dpk.getAlgorithm() == DNSSEC::ECCGOST ? "www.example.net." : "example.com.");

  RRSIGRecordContent rrc;
  uint32_t expire = 1440021600;
  uint32_t inception = 1438207200;

  if (dpk.getAlgorithm() == DNSSEC::ECCGOST) {
    rrc.d_signer = DNSName("example.net.");
    inception = 946684800;
    expire = 1893456000;
    rrs.insert(DNSRecordContent::make(QType::A, QClass::IN, "192.0.2.1"));
  }
  else {
    rrc.d_signer = qname;
    rrs.insert(DNSRecordContent::make(QType::MX, QClass::IN, "10 mail.example.com."));
  }

  rrc.d_originalttl = 3600;
  rrc.d_sigexpire = expire;
  rrc.d_siginception = inception;
  rrc.d_type = (*rrs.cbegin())->getType();
  rrc.d_labels = qname.countLabels();
  rrc.d_tag = dpk.getTag();
  rrc.d_algorithm = dpk.getAlgorithm();

  string msg = getMessageForRRSET(qname, rrc, rrs, false);

  BOOST_CHECK_EQUAL(makeHexDump(msg), signer.rfcMsgDump);

  string signature = dcke->sign(msg);

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): Boost stuff.
  BOOST_CHECK(dcke->verify(msg, signature));

  if (signer.isDeterministic) {
    string b64 = Base64Encode(signature);
    BOOST_CHECK_EQUAL(b64, signer.rfcB64Signature);
  }
  else {
    std::string raw;
    B64Decode(signer.rfcB64Signature, raw);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): Boost stuff.
    BOOST_CHECK(dcke->verify(msg, raw));
  }
}

static void test_generic_signer(std::shared_ptr<DNSCryptoKeyEngine> dcke, DNSKEYRecordContent& drc, const SignerParams& signer, const std::string& message)
{
  BOOST_CHECK_EQUAL(dcke->getAlgorithm(), signer.algorithm);
  BOOST_CHECK_EQUAL(dcke->getBits(), signer.bits);

  vector<string> errorMessages{};
  BOOST_CHECK_EQUAL(dcke->checkKey(errorMessages), true);
  if (!errorMessages.empty()) {
    BOOST_TEST_MESSAGE("Errors from " + dcke->getName() + " checkKey()");
    for (auto& errorMessage : errorMessages) {
      BOOST_TEST_MESSAGE("  " + errorMessage);
    }
  }

  BOOST_CHECK_EQUAL(drc.d_algorithm, signer.algorithm);

  DNSSECPrivateKey dpk;
  dpk.setKey(dcke, signer.flags);
  drc = dpk.getDNSKEY();

  BOOST_CHECK_EQUAL(drc.d_algorithm, signer.algorithm);
  BOOST_CHECK_EQUAL(drc.d_protocol, 3);
  BOOST_CHECK_EQUAL(drc.getZoneRepresentation(), signer.zoneRepresentation);

  DNSName name(signer.name);
  auto ds1 = makeDSFromDNSKey(name, drc, DNSSEC::DIGEST_SHA1);
  if (!signer.dsSHA1.empty()) {
    BOOST_CHECK_EQUAL(ds1.getZoneRepresentation(), signer.dsSHA1);
  }

  auto ds2 = makeDSFromDNSKey(name, drc, DNSSEC::DIGEST_SHA256);
  if (!signer.dsSHA256.empty()) {
    BOOST_CHECK_EQUAL(ds2.getZoneRepresentation(), signer.dsSHA256);
  }

  auto ds4 = makeDSFromDNSKey(name, drc, DNSSEC::DIGEST_SHA384);
  if (!signer.dsSHA384.empty()) {
    BOOST_CHECK_EQUAL(ds4.getZoneRepresentation(), signer.dsSHA384);
  }

  auto signature = dcke->sign(message);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): Boost stuff.
  BOOST_CHECK(dcke->verify(message, signature));

  auto signerSignature = std::string(signer.signature.begin(), signer.signature.end());
  if (signer.isDeterministic) {
    auto signatureBase64 = Base64Encode(signature);
    auto signerSignatureBase64 = Base64Encode(signerSignature);
    BOOST_CHECK_EQUAL(signatureBase64, signerSignatureBase64);
  }
  else {
    /* since the signing process is not deterministic, we can't directly compare our signature
       with the one we have. Still the one we have should also validate correctly. */
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): Boost stuff.
    BOOST_CHECK(dcke->verify(message, signerSignature));
  }

  if (!signer.rfcMsgDump.empty() && !signer.rfcB64Signature.empty()) {
    checkRR(signer);
  }
}

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables,readability-identifier-length): Boost stuff.
BOOST_FIXTURE_TEST_CASE(test_generic_signers, Fixture)
{
  for (const auto& algoSignerPair : signerParams) {
    auto signer = algoSignerPair.second;

    DNSKEYRecordContent drc;
    auto dcke = std::shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::makeFromISCString(drc, signer.iscMap));
    test_generic_signer(dcke, drc, signer, message);

    DNSKEYRecordContent pemDRC;
    shared_ptr<DNSCryptoKeyEngine> pemKey{DNSCryptoKeyEngine::makeFromPEMString(pemDRC, signer.algorithm, signer.pem)};

    BOOST_CHECK_EQUAL(pemKey->convertToISC(), dcke->convertToISC());

    test_generic_signer(pemKey, pemDRC, signer, message);

    auto dckePEMOutput = dcke->convertToPEMString();
    BOOST_CHECK_EQUAL(dckePEMOutput, signer.pem);

    auto pemKeyOutput = pemKey->convertToPEMString();
    BOOST_CHECK_EQUAL(pemKeyOutput, signer.pem);
  }
}

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables,readability-identifier-length): Boost stuff.
BOOST_AUTO_TEST_CASE(test_hash_qname_with_salt)
{
  {
    // rfc5155 appendix A
    const unsigned char salt[] = {0xaa, 0xbb, 0xcc, 0xdd};
    const unsigned int iterations{12};
    const std::vector<std::pair<std::string, std::string>> namesToHashes = {
      {"example", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"},
      {"a.example", "35mthgpgcu1qg68fab165klnsnk3dpvl"},
      {"ai.example", "gjeqe526plbf1g8mklp59enfd789njgi"},
      {"ns1.example", "2t7b4g4vsa5smi47k61mv5bv1a22bojr"},
      {"ns2.example", "q04jkcevqvmu85r014c7dkba38o0ji5r"},
      {"w.example", "k8udemvp1j2f7eg6jebps17vp3n8i58h"},
      {"*.w.example", "r53bq7cc2uvmubfu5ocmm6pers9tk9en"},
      {"x.w.example", "b4um86eghhds6nea196smvmlo4ors995"},
      {"y.w.example", "ji6neoaepv8b5o6k4ev33abha8ht9fgc"},
      {"x.y.w.example", "2vptu5timamqttgl4luu9kg21e0aor3s"},
      {"xx.example", "t644ebqk9bibcna874givr6joj62mlhv"},
      {"2t7b4g4vsa5smi47k61mv5bv1a22bojr.example", "kohar7mbb8dc2ce8a9qvl8hon4k53uhi"},
    };

    for (const auto& [name, expectedHash] : namesToHashes) {
      auto hash = hashQNameWithSalt(std::string(reinterpret_cast<const char*>(salt), sizeof(salt)), iterations, DNSName(name));
      BOOST_CHECK_EQUAL(toBase32Hex(hash), expectedHash);
    }
  }

  {
    /* no additional iterations, very short salt */
    const unsigned char salt[] = {0xFF};
    const unsigned int iterations{0};
    const std::vector<std::pair<std::string, std::string>> namesToHashes = {
      {"example", "s9dp8o2l6jgqgg26ecobtjooe7p019cs"},
    };

    for (const auto& [name, expectedHash] : namesToHashes) {
      auto hash = hashQNameWithSalt(std::string(reinterpret_cast<const char*>(salt), sizeof(salt)), iterations, DNSName(name));
      BOOST_CHECK_EQUAL(toBase32Hex(hash), expectedHash);
    }
  }

  {
    /* only one iteration */
    const unsigned char salt[] = {0xaa, 0xbb, 0xcc, 0xdd};
    const unsigned int iterations{1};
    const std::vector<std::pair<std::string, std::string>> namesToHashes = {
      {"example", "ulddquehrj5jpf50ga76vgqr1oq40133"},
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
      {"example", "no95j4cfile8avstr7bn4aj9he18trri"},
    };

    for (const auto& [name, expectedHash] : namesToHashes) {
      auto hash = hashQNameWithSalt(std::string(reinterpret_cast<const char*>(salt), sizeof(salt)), iterations, DNSName(name));
      BOOST_CHECK_EQUAL(toBase32Hex(hash), expectedHash);
    }
  }
}

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): Boost stuff.
BOOST_AUTO_TEST_SUITE_END()
