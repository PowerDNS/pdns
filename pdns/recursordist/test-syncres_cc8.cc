#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include "test-syncres_cc.hh"

BOOST_AUTO_TEST_SUITE(syncres_cc8)

BOOST_AUTO_TEST_CASE(test_nsec_denial_nowrap) {
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("example.org."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  /*
    No wrap test case:
    a.example.org. -> d.example.org. denies the existence of b.example.org.
   */
  addNSECRecordToLW(DNSName("a.example.org."), DNSName("d.example.org"), { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(DNSName("a.example.org."), QType::NSEC)] = pair;

  /* add wildcard denial */
  recordContents.clear();
  signatureContents.clear();
  addNSECRecordToLW(DNSName("example.org."), DNSName("+.example.org"), { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::make_pair(DNSName("example.org."), QType::NSEC)] = pair;

  dState denialState = getDenial(denialMap, DNSName("b.example.org."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, NXDOMAIN);

  denialState = getDenial(denialMap, DNSName("d.example.org."), QType::A, false, false);
  /* let's check that d.example.org. is not denied by this proof */
  BOOST_CHECK_EQUAL(denialState, NODATA);
}

BOOST_AUTO_TEST_CASE(test_nsec_denial_wrap_case_1) {
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("example.org."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  /*
    Wrap case 1 test case:
    z.example.org. -> b.example.org. denies the existence of a.example.org.
   */
  addNSECRecordToLW(DNSName("z.example.org."), DNSName("b.example.org"), { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(DNSName("z.example.org."), QType::NSEC)] = pair;

  dState denialState = getDenial(denialMap, DNSName("a.example.org."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, NXDOMAIN);

  denialState = getDenial(denialMap, DNSName("d.example.org."), QType::A, false, false);
  /* let's check that d.example.org. is not denied by this proof */
  BOOST_CHECK_EQUAL(denialState, NODATA);
}

BOOST_AUTO_TEST_CASE(test_nsec_denial_wrap_case_2) {
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("example.org."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  /*
    Wrap case 2 test case:
    y.example.org. -> a.example.org. denies the existence of z.example.org.
   */
  addNSECRecordToLW(DNSName("y.example.org."), DNSName("a.example.org"), { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(DNSName("y.example.org."), QType::NSEC)] = pair;

  dState denialState = getDenial(denialMap, DNSName("z.example.org."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, NXDOMAIN);

  denialState = getDenial(denialMap, DNSName("d.example.org."), QType::A, false, false);
  /* let's check that d.example.org. is not denied by this proof */
  BOOST_CHECK_EQUAL(denialState, NODATA);
}

BOOST_AUTO_TEST_CASE(test_nsec_denial_only_one_nsec) {
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("example.org."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  /*
    Only one NSEC in the whole zone test case:
    a.example.org. -> a.example.org. denies the existence of b.example.org.
   */
  addNSECRecordToLW(DNSName("a.example.org."), DNSName("a.example.org"), { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(DNSName("a.example.org."), QType::NSEC)] = pair;

  dState denialState = getDenial(denialMap, DNSName("b.example.org."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, NXDOMAIN);

  denialState = getDenial(denialMap, DNSName("a.example.org."), QType::A, false, false);
  /* let's check that d.example.org. is not denied by this proof */
  BOOST_CHECK_EQUAL(denialState, NODATA);
}

BOOST_AUTO_TEST_CASE(test_nsec_root_nxd_denial) {
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  /*
    The RRSIG from "." denies the existence of anything between a. and c.,
    including b.
  */
  addNSECRecordToLW(DNSName("a."), DNSName("c."), { QType::NS }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(DNSName("a."), QType::NSEC)] = pair;

  /* add wildcard denial */
  recordContents.clear();
  signatureContents.clear();
  addNSECRecordToLW(DNSName("."), DNSName("+"), { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::make_pair(DNSName("."), QType::NSEC)] = pair;

  dState denialState = getDenial(denialMap, DNSName("b."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, NXDOMAIN);
}

BOOST_AUTO_TEST_CASE(test_nsec_ancestor_nxqtype_denial) {
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  /*
    The RRSIG from "." denies the existence of any type except NS at a.
    However since it's an ancestor delegation NSEC (NS bit set, SOA bit clear,
    signer field that is shorter than the owner name of the NSEC RR) it can't
    be used to deny anything except the whole name or a DS.
  */
  addNSECRecordToLW(DNSName("a."), DNSName("b."), { QType::NS }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(DNSName("a."), QType::NSEC)] = pair;

  /* RFC 6840 section 4.1 "Clarifications on Nonexistence Proofs":
     Ancestor delegation NSEC or NSEC3 RRs MUST NOT be used to assume
     nonexistence of any RRs below that zone cut, which include all RRs at
     that (original) owner name other than DS RRs, and all RRs below that
     owner name regardless of type.
  */

  dState denialState = getDenial(denialMap, DNSName("a."), QType::A, false, false);
  /* no data means the qname/qtype is not denied, because an ancestor
     delegation NSEC can only deny the DS */
  BOOST_CHECK_EQUAL(denialState, NODATA);

  /* it can not be used to deny any RRs below that owner name either */
  denialState = getDenial(denialMap, DNSName("sub.a."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, NODATA);

  denialState = getDenial(denialMap, DNSName("a."), QType::DS, true, true);
  BOOST_CHECK_EQUAL(denialState, NXQTYPE);
}

BOOST_AUTO_TEST_CASE(test_nsec_insecure_delegation_denial) {
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  /*
   * RFC 5155 section 8.9:
   * If there is an NSEC3 RR present in the response that matches the
   * delegation name, then the validator MUST ensure that the NS bit is
   * set and that the DS bit is not set in the Type Bit Maps field of the
   * NSEC3 RR.
   */
  /*
    The RRSIG from "." denies the existence of any type at a.
    NS should be set if it was proving an insecure delegation, let's check that
    we correctly detect that it's not.
  */
  addNSECRecordToLW(DNSName("a."), DNSName("b."), { }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(DNSName("a."), QType::NSEC)] = pair;

  /* Insecure because the NS is not set, so while it does
     denies the DS, it can't prove an insecure delegation */
  dState denialState = getDenial(denialMap, DNSName("a."), QType::DS, true, true);
  BOOST_CHECK_EQUAL(denialState, NODATA);
}

BOOST_AUTO_TEST_CASE(test_nsec_nxqtype_cname) {
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  addNSECRecordToLW(DNSName("a.powerdns.com."), DNSName("a.c.powerdns.com."), { QType::CNAME }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(DNSName("a.powerdns.com."), QType::NSEC)] = pair;

  /* this NSEC is not valid to deny a.powerdns.com|A since it states that a CNAME exists */
  dState denialState = getDenial(denialMap, DNSName("a.powerdns.com."), QType::A, true, true);
  BOOST_CHECK_EQUAL(denialState, NODATA);
}

BOOST_AUTO_TEST_CASE(test_nsec3_nxqtype_cname) {
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  addNSEC3UnhashedRecordToLW(DNSName("a.powerdns.com."), DNSName("powerdns.com."), "whatever", { QType::CNAME }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(records.at(0).d_name, records.at(0).d_type)] = pair;
  records.clear();

  /* this NSEC3 is not valid to deny a.powerdns.com|A since it states that a CNAME exists */
  dState denialState = getDenial(denialMap, DNSName("a.powerdns.com."), QType::A, false, true);
  BOOST_CHECK_EQUAL(denialState, NODATA);
}

BOOST_AUTO_TEST_CASE(test_nsec_nxdomain_denial_missing_wildcard) {
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  addNSECRecordToLW(DNSName("a.powerdns.com."), DNSName("d.powerdns.com"), { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(DNSName("a.powerdns.com."), QType::NSEC)] = pair;

  dState denialState = getDenial(denialMap, DNSName("b.powerdns.com."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, NODATA);
}

BOOST_AUTO_TEST_CASE(test_nsec3_nxdomain_denial_missing_wildcard) {
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  addNSEC3NarrowRecordToLW(DNSName("a.powerdns.com."), DNSName("powerdns.com."), { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  /* Add NSEC3 for the closest encloser */
  recordContents.clear();
  signatureContents.clear();
  records.clear();
  addNSEC3UnhashedRecordToLW(DNSName("powerdns.com."), DNSName("powerdns.com."), "whatever", { QType::A, QType::TXT, QType::RRSIG, QType::NSEC }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::make_pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  dState denialState = getDenial(denialMap, DNSName("b.powerdns.com."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, NODATA);
}

BOOST_AUTO_TEST_CASE(test_nsec_ent_denial) {
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("powerdns.com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  addNSECRecordToLW(DNSName("a.powerdns.com."), DNSName("a.c.powerdns.com."), { QType::A }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(DNSName("a.powerdns.com."), QType::NSEC)] = pair;

  /* this NSEC is valid to prove a NXQTYPE at c.powerdns.com because it proves that
     it is an ENT */
  dState denialState = getDenial(denialMap, DNSName("c.powerdns.com."), QType::AAAA, true, true);
  BOOST_CHECK_EQUAL(denialState, NXQTYPE);

  /* this NSEC is not valid to prove a NXQTYPE at b.powerdns.com,
     it could prove a NXDOMAIN if it had an additional wildcard denial */
  denialState = getDenial(denialMap, DNSName("b.powerdns.com."), QType::AAAA, true, true);
  BOOST_CHECK_EQUAL(denialState, NODATA);

  /* this NSEC is not valid to prove a NXQTYPE for QType::A at a.c.powerdns.com either */
  denialState = getDenial(denialMap, DNSName("a.c.powerdns.com."), QType::A, true, true);
  BOOST_CHECK_EQUAL(denialState, NODATA);

  /* if we add the wildcard denial proof, we should get a NXDOMAIN proof for b.powerdns.com */
  recordContents.clear();
  signatureContents.clear();
  addNSECRecordToLW(DNSName(").powerdns.com."), DNSName("+.powerdns.com."), { }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();
  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::make_pair(DNSName(").powerdns.com."), QType::NSEC)] = pair;

  denialState = getDenial(denialMap, DNSName("b.powerdns.com."), QType::A, true, false);
  BOOST_CHECK_EQUAL(denialState, NXDOMAIN);
}

BOOST_AUTO_TEST_CASE(test_nsec3_ancestor_nxqtype_denial) {
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  /*
    The RRSIG from "." denies the existence of any type except NS at a.
    However since it's an ancestor delegation NSEC (NS bit set, SOA bit clear,
    signer field that is shorter than the owner name of the NSEC RR) it can't
    be used to deny anything except the whole name or a DS.
  */
  addNSEC3UnhashedRecordToLW(DNSName("a."), DNSName("."), "whatever", { QType::NS }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(records.at(0).d_name, records.at(0).d_type)] = pair;
  records.clear();

  /* RFC 6840 section 4.1 "Clarifications on Nonexistence Proofs":
     Ancestor delegation NSEC or NSEC3 RRs MUST NOT be used to assume
     nonexistence of any RRs below that zone cut, which include all RRs at
     that (original) owner name other than DS RRs, and all RRs below that
     owner name regardless of type.
  */

  dState denialState = getDenial(denialMap, DNSName("a."), QType::A, false, true);
  /* no data means the qname/qtype is not denied, because an ancestor
     delegation NSEC3 can only deny the DS */
  BOOST_CHECK_EQUAL(denialState, NODATA);

  denialState = getDenial(denialMap, DNSName("a."), QType::DS, true, true);
  BOOST_CHECK_EQUAL(denialState, NXQTYPE);

  /* it can not be used to deny any RRs below that owner name either */
  /* Add NSEC3 for the next closer */
  recordContents.clear();
  signatureContents.clear();
  records.clear();
  addNSEC3NarrowRecordToLW(DNSName("sub.a."), DNSName("."), { QType::A, QType::TXT, QType::RRSIG, QType::NSEC3 }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::make_pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  /* add wildcard denial */
  recordContents.clear();
  signatureContents.clear();
  records.clear();
  addNSEC3NarrowRecordToLW(DNSName("*.a."), DNSName("."), { QType::A, QType::TXT, QType::RRSIG, QType::NSEC3 }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::make_pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  denialState = getDenial(denialMap, DNSName("sub.a."), QType::A, false, true);
  BOOST_CHECK_EQUAL(denialState, NODATA);
}

BOOST_AUTO_TEST_CASE(test_nsec3_denial_too_many_iterations) {
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  /* adding a NSEC3 with more iterations that we support */
  addNSEC3UnhashedRecordToLW(DNSName("a."), DNSName("."), "whatever", { QType::AAAA }, 600, records, g_maxNSEC3Iterations + 100);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(records.at(0).d_name, records.at(0).d_type)] = pair;
  records.clear();

  dState denialState = getDenial(denialMap, DNSName("a."), QType::A, false, true);
  /* since we refuse to compute more than g_maxNSEC3Iterations iterations, it should be Insecure */
  BOOST_CHECK_EQUAL(denialState, INSECURE);
}

BOOST_AUTO_TEST_CASE(test_nsec3_insecure_delegation_denial) {
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  vector<shared_ptr<DNSRecordContent>> recordContents;
  vector<shared_ptr<RRSIGRecordContent>> signatureContents;

  /*
   * RFC 5155 section 8.9:
   * If there is an NSEC3 RR present in the response that matches the
   * delegation name, then the validator MUST ensure that the NS bit is
   * set and that the DS bit is not set in the Type Bit Maps field of the
   * NSEC3 RR.
   */
  /*
    The RRSIG from "." denies the existence of any type at a.
    NS should be set if it was proving an insecure delegation, let's check that
    we correctly detect that it's not.
  */
  addNSEC3UnhashedRecordToLW(DNSName("a."), DNSName("."), "whatever", { }, 600, records);
  recordContents.push_back(records.at(0).d_content);
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::make_pair(records.at(0).d_name, records.at(0).d_type)] = pair;
  records.clear();

  /* Insecure because the NS is not set, so while it does
     denies the DS, it can't prove an insecure delegation */
  dState denialState = getDenial(denialMap, DNSName("a."), QType::DS, true, true);
  BOOST_CHECK_EQUAL(denialState, NODATA);
}

BOOST_AUTO_TEST_CASE(test_dnssec_rrsig_negcache_validity) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;
  const time_t fixedNow = sr->getNow().tv_sec;

  sr->setAsyncCallback([target,&queriesCount,keys,fixedNow](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      DNSName auth = domain;
      auth.chopOff();

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
      }
      else {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
        addRRSIG(keys, res->d_records, domain, 300);
        addNSECRecordToLW(domain, DNSName("z."), { QType::NSEC, QType::RRSIG }, 600, res->d_records);
        addRRSIG(keys, res->d_records, domain, 1, false, boost::none, boost::none, fixedNow);
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* check that the entry has not been negatively cached for longer than the RRSIG validity */
  const NegCache::NegCacheEntry* ne = nullptr;
  BOOST_CHECK_EQUAL(SyncRes::t_sstorage.negcache.size(), 1U);
  BOOST_REQUIRE_EQUAL(SyncRes::t_sstorage.negcache.get(target, QType(QType::A), sr->getNow(), &ne), true);
  BOOST_CHECK_EQUAL(ne->d_ttd, fixedNow + 1);
  BOOST_CHECK_EQUAL(ne->d_validationState, Secure);
  BOOST_CHECK_EQUAL(ne->authoritySOA.records.size(), 1U);
  BOOST_CHECK_EQUAL(ne->authoritySOA.signatures.size(), 1U);
  BOOST_CHECK_EQUAL(ne->DNSSECRecords.records.size(), 1U);
  BOOST_CHECK_EQUAL(ne->DNSSECRecords.signatures.size(), 1U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_rrsig_negcache_bogus_validity) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;
  const time_t fixedNow = sr->getNow().tv_sec;

  sr->setAsyncCallback([&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      DNSName auth = domain;
      auth.chopOff();

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
      }
      else {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 86400);
        addRRSIG(keys, res->d_records, domain, 86400);
        addNSECRecordToLW(domain, DNSName("z."), { QType::NSEC, QType::RRSIG }, 86400, res->d_records);
        /* no RRSIG */
        return 1;
      }

      return 0;
    });

  SyncRes::s_maxnegttl = 3600;
  SyncRes::s_maxbogusttl = 360;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* check that the entry has been negatively cached but not longer than s_maxbogusttl */
  const NegCache::NegCacheEntry* ne = nullptr;
  BOOST_CHECK_EQUAL(SyncRes::t_sstorage.negcache.size(), 1U);
  BOOST_REQUIRE_EQUAL(SyncRes::t_sstorage.negcache.get(target, QType(QType::A), sr->getNow(), &ne), true);
  BOOST_CHECK_EQUAL(ne->d_ttd, fixedNow + SyncRes::s_maxbogusttl);
  BOOST_CHECK_EQUAL(ne->d_validationState, Bogus);
  BOOST_CHECK_EQUAL(ne->authoritySOA.records.size(), 1U);
  BOOST_CHECK_EQUAL(ne->authoritySOA.signatures.size(), 1U);
  BOOST_CHECK_EQUAL(ne->DNSSECRecords.records.size(), 1U);
  BOOST_CHECK_EQUAL(ne->DNSSECRecords.signatures.size(), 0U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_rrsig_cache_validity) {
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("com.");
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;
  const time_t tnow = sr->getNow().tv_sec;

  sr->setAsyncCallback([target,targetAddr,&queriesCount,keys,tnow](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      DNSName auth = domain;
      auth.chopOff();

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
      }
      else {
        setLWResult(res, RCode::NoError, true, false, true);
        addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
        addRRSIG(keys, res->d_records, domain, 1, false, boost::none, boost::none, tnow);
        return 1;
      }

      return 0;
    });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* check that the entry has not been cached for longer than the RRSIG validity */
  const ComboAddress who;
  vector<DNSRecord> cached;
  vector<std::shared_ptr<RRSIGRecordContent>> signatures;
  BOOST_REQUIRE_EQUAL(t_RC->get(tnow, target, QType(QType::A), true, &cached, who, &signatures), 1);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
  BOOST_REQUIRE_EQUAL(signatures.size(), 1U);
  BOOST_CHECK_EQUAL((cached[0].d_ttl - tnow), 1);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_cache_secure) {
  /*
    Validation is optional, and the first query does not ask for it,
    so the answer is cached as Indeterminate.
    The second query asks for validation, answer should be marked as
    Secure, after just-in-time validation.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
      }
      else {
        if (domain == target && type == QType::A) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, target, QType::A, "192.0.2.1");
          addRRSIG(keys, res->d_records, DNSName("."), 300);
          return 1;
        }
      }

      return 0;
    });

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::A || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 1U);


  ret.clear();
  /* second one _does_ require validation */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::A || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 3U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_cache_insecure) {
  /*
    Validation is optional, and the first query does not ask for it,
    so the answer is cached as Indeterminate.
    The second query asks for validation, answer should be marked as
    Insecure.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
      }
      else {
        if (domain == target && type == QType::A) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, target, QType::A, "192.0.2.1");
          return 1;
        }
      }

      return 0;
    });

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::A);
  }
  BOOST_CHECK_EQUAL(queriesCount, 1U);


  ret.clear();
  /* second one _does_ require validation */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::A);
  }
  BOOST_CHECK_EQUAL(queriesCount, 1U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_cache_bogus) {
  /*
    Validation is optional, and the first query does not ask for it,
    so the answer is cached as Indeterminate.
    The second query asks for validation, answer should be marked as
    Bogus.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSECKeeper::ECDSA256, DNSSECKeeper::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([target,&queriesCount,keys](const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, LWResult* res, bool* chained) {
      queriesCount++;

      if (type == QType::DS || type == QType::DNSKEY) {
        return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
      }
      else {
        if (domain == target && type == QType::A) {
          setLWResult(res, 0, true, false, true);
          addRecordToLW(res, target, QType::A, "192.0.2.1", DNSResourceRecord::ANSWER, 86400);
          /* no RRSIG */
          return 1;
        }
      }

      return 0;
    });

  SyncRes::s_maxbogusttl = 3600;

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::A);
    BOOST_CHECK_EQUAL(record.d_ttl, 86400U);
  }
  BOOST_CHECK_EQUAL(queriesCount, 1U);


  ret.clear();
  /* second one _does_ require validation */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  /* check that we correctly capped the TTD for a Bogus record after
     just-in-time validation */
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::A);
    BOOST_CHECK_EQUAL(record.d_ttl, SyncRes::s_maxbogusttl);
  }
  BOOST_CHECK_EQUAL(queriesCount, 3U);

  ret.clear();
  /* third time also _does_ require validation, so we
     can check that the cache has been updated */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), Bogus);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::A);
    BOOST_CHECK_EQUAL(record.d_ttl, SyncRes::s_maxbogusttl);
  }
  BOOST_CHECK_EQUAL(queriesCount, 3U);
}

BOOST_AUTO_TEST_SUITE_END()
