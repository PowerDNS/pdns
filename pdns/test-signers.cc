#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>

#include <boost/tuple/tuple.hpp>
#include <boost/scoped_ptr.hpp>

#include "base64.hh"
#include "dnsseckeeper.hh"
#include "dnssecinfra.hh"
#include "misc.hh"

BOOST_AUTO_TEST_SUITE(test_signers)

#ifdef HAVE_LIBSODIUM
BOOST_AUTO_TEST_CASE(test_ed25519_signer) {
    vector<std::shared_ptr<DNSRecordContent> > rrs;
    DNSName qname("example.com.");
    DNSKEYRecordContent drc;

    // TODO: make this a collection of inputs and resulting sigs for various algos
    shared_ptr<DNSCryptoKeyEngine> engine = DNSCryptoKeyEngine::makeFromISCString(drc,
"Private-key-format: v1.2\n"
"Algorithm: 15 (ED25519)\n"
"PrivateKey: ODIyNjAzODQ2MjgwODAxMjI2NDUxOTAyMDQxNDIyNjI=");

    DNSSECPrivateKey dpk;
    dpk.setKey(engine);

    reportBasicTypes();

    rrs.push_back(DNSRecordContent::makeunique(QType::MX, 1, "10 mail.example.com."));

    RRSIGRecordContent rrc;
    rrc.d_originalttl = 3600;
    rrc.d_sigexpire = 1440021600;
    rrc.d_siginception = 1438207200;
    rrc.d_signer = qname;
    rrc.d_type = QType::MX;
    rrc.d_labels = 2;
    // TODO: derive the next two from the key
    rrc.d_tag = 3613;
    rrc.d_algorithm = 15;

    string msg = getMessageForRRSET(qname, rrc, rrs, false);

    // vector extracted from https://gitlab.labs.nic.cz/labs/ietf/blob/master/dnskey.py (rev 476d6ded) by printing signature_data
    BOOST_CHECK_EQUAL(makeHexDump(msg), "00 0f 0f 02 00 00 0e 10 55 d4 fc 60 55 b9 4c e0 0e 1d 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 0f 00 01 00 00 0e 10 00 14 00 0a 04 6d 61 69 6c 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ");

    string signature = engine->sign(msg);
    string b64 = Base64Encode(signature);

    // vector verified from dnskey.py as above, and confirmed with https://www.rfc-editor.org/errata_search.php?rfc=8080&eid=4935
    BOOST_CHECK_EQUAL(b64, "oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3fx8A4M3e23mRZ9VrbpMngwcrqNAg==");
}
#endif

BOOST_AUTO_TEST_SUITE_END()
