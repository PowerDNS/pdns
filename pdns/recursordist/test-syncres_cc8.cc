#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#include <boost/test/unit_test.hpp>

#include "test-syncres_cc.hh"

BOOST_AUTO_TEST_SUITE(syncres_cc8)

static dState getDenial(const cspmap_t& validrrsets, const DNSName& qname, uint16_t qtype, bool referralToUnsigned, bool wantsNoDataProof, const OptLog& log = std::nullopt, bool needWildcardProof = true, unsigned int wildcardLabelsCount = 0)
{
  pdns::validation::ValidationContext context;
  context.d_nsec3IterationsRemainingQuota = std::numeric_limits<decltype(context.d_nsec3IterationsRemainingQuota)>::max();
  return getDenial(validrrsets, qname, qtype, referralToUnsigned, wantsNoDataProof, context, log, needWildcardProof, wildcardLabelsCount);
}

BOOST_AUTO_TEST_CASE(test_nsec_denial_nowrap)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("example.org."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  /*
    No wrap test case:
    a.example.org. -> d.example.org. denies the existence of b.example.org.
   */
  addNSECRecordToLW(DNSName("a.example.org."), DNSName("d.example.org"), {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(DNSName("a.example.org."), QType::NSEC)] = pair;

  /* add wildcard denial */
  recordContents.clear();
  signatureContents.clear();
  addNSECRecordToLW(DNSName("example.org."), DNSName("+.example.org"), {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::pair(DNSName("example.org."), QType::NSEC)] = pair;

  dState denialState = getDenial(denialMap, DNSName("b.example.org."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, dState::NXDOMAIN);

  denialState = getDenial(denialMap, DNSName("d.example.org."), QType::A, false, false);
  /* let's check that d.example.org. is not denied by this proof */
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);
}

BOOST_AUTO_TEST_CASE(test_nsec_denial_wrap_case_1)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("example.org."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  /*
    Wrap case 1 test case:
    z.example.org. -> b.example.org. denies the existence of a.example.org.
   */
  addNSECRecordToLW(DNSName("z.example.org."), DNSName("b.example.org"), {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(DNSName("z.example.org."), QType::NSEC)] = pair;

  dState denialState = getDenial(denialMap, DNSName("a.example.org."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, dState::NXDOMAIN);

  denialState = getDenial(denialMap, DNSName("d.example.org."), QType::A, false, false);
  /* let's check that d.example.org. is not denied by this proof */
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);
}

BOOST_AUTO_TEST_CASE(test_nsec_denial_wrap_case_2)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("example.org."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  /*
    Wrap case 2 test case:
    y.example.org. -> a.example.org. denies the existence of z.example.org.
   */
  addNSECRecordToLW(DNSName("y.example.org."), DNSName("a.example.org"), {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(DNSName("y.example.org."), QType::NSEC)] = pair;

  dState denialState = getDenial(denialMap, DNSName("z.example.org."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, dState::NXDOMAIN);

  denialState = getDenial(denialMap, DNSName("d.example.org."), QType::A, false, false);
  /* let's check that d.example.org. is not denied by this proof */
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);
}

BOOST_AUTO_TEST_CASE(test_nsec_denial_only_one_nsec)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("example.org."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  /*
    Only one NSEC in the whole zone test case:
    a.example.org. -> a.example.org. denies the existence of b.example.org.
   */
  addNSECRecordToLW(DNSName("a.example.org."), DNSName("a.example.org"), {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(DNSName("a.example.org."), QType::NSEC)] = pair;

  dState denialState = getDenial(denialMap, DNSName("b.example.org."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, dState::NXDOMAIN);

  denialState = getDenial(denialMap, DNSName("a.example.org."), QType::A, false, false);
  /* let's check that d.example.org. is not denied by this proof */
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);
}

BOOST_AUTO_TEST_CASE(test_nsec_root_nxd_denial)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  /*
    The RRSIG from "." denies the existence of anything between a. and c.,
    including b.
  */
  addNSECRecordToLW(DNSName("a."), DNSName("c."), {QType::NS}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(DNSName("a."), QType::NSEC)] = pair;

  /* add wildcard denial */
  recordContents.clear();
  signatureContents.clear();
  addNSECRecordToLW(DNSName("."), DNSName("+"), {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::pair(DNSName("."), QType::NSEC)] = pair;

  dState denialState = getDenial(denialMap, DNSName("b."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, dState::NXDOMAIN);
}

BOOST_AUTO_TEST_CASE(test_nsec_ancestor_nxqtype_denial)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  /*
    The RRSIG from "." denies the existence of any type except NS at a.
    However since it's an ancestor delegation NSEC (NS bit set, SOA bit clear,
    signer field that is shorter than the owner name of the NSEC RR) it can't
    be used to deny anything except the whole name (which does not make sense here)
    or a DS.
  */
  addNSECRecordToLW(DNSName("a."), DNSName("b."), {QType::NS}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(DNSName("a."), QType::NSEC)] = pair;

  /* RFC 6840 section 4.1 "Clarifications on Nonexistence Proofs":
     Ancestor delegation NSEC or NSEC3 RRs MUST NOT be used to assume
     nonexistence of any RRs below that zone cut, which include all RRs at
     that (original) owner name other than DS RRs, and all RRs below that
     owner name regardless of type.
  */

  dState denialState = getDenial(denialMap, DNSName("a."), QType::A, false, true);
  /* no data means the qname/qtype is not denied, because an ancestor
     delegation NSEC can only deny the DS */
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);

  /* it can not be used to deny any RRs below that owner name either */
  denialState = getDenial(denialMap, DNSName("sub.a."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);

  denialState = getDenial(denialMap, DNSName("a."), QType::DS, true, true);
  BOOST_CHECK_EQUAL(denialState, dState::NXQTYPE);
}

BOOST_AUTO_TEST_CASE(test_nsec_ds_denial_from_child)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("org."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("example.org."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  addNSECRecordToLW(DNSName("example.org."), DNSName("a.example.org"), {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(DNSName("example.org."), QType::NSEC)] = pair;

  /* check that this NSEC from the child zone can deny a AAAA at the apex */
  BOOST_CHECK_EQUAL(getDenial(denialMap, DNSName("example.org."), QType::AAAA, false, true, std::nullopt, true), dState::NXQTYPE);

  /* but not that the DS does not exist, since we need the parent for that */
  BOOST_CHECK_EQUAL(getDenial(denialMap, DNSName("example.org."), QType::DS, false, true, std::nullopt, true), dState::NODENIAL);
}

BOOST_AUTO_TEST_CASE(test_nsec_insecure_delegation_denial)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

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
  addNSECRecordToLW(DNSName("a."), DNSName("b."), {}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(DNSName("a."), QType::NSEC)] = pair;

  /* Insecure because the NS is not set, so while it does
     denies the DS, it can't prove an insecure delegation */
  dState denialState = getDenial(denialMap, DNSName("a."), QType::DS, true, true);
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);
}

BOOST_AUTO_TEST_CASE(test_nsec_insecure_delegation_denial_soa)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  /*
   * RFC 5155 section 8.9:
   * If there is an NSEC3 RR present in the response that matches the
   * delegation name, then the validator MUST ensure that the NS bit is
   * set and that the DS bit is not set in the Type Bit Maps field of the
   * NSEC3 RR.
   */
  /*
    The RRSIG from "." denies the existence of any type at "a" except NS and SOA.
    NS has to be set since it is proving an insecure delegation, but SOA should NOT!
  */
  addNSECRecordToLW(DNSName("a."), DNSName("b."), {QType::NS, QType::SOA}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(DNSName("a."), QType::NSEC)] = pair;

  /* Insecure because both NS and SOA are set, so this is not a proper delegation */
  dState denialState = getDenial(denialMap, DNSName("a."), QType::DS, true, true);
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);
}

BOOST_AUTO_TEST_CASE(test_nsec_nxqtype_cname)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  addNSECRecordToLW(DNSName("a.powerdns.com."), DNSName("a.c.powerdns.com."), {QType::CNAME}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(DNSName("a.powerdns.com."), QType::NSEC)] = pair;

  /* this NSEC is not valid to deny a.powerdns.com|A since it states that a CNAME exists */
  dState denialState = getDenial(denialMap, DNSName("a.powerdns.com."), QType::A, true, true);
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);
}

BOOST_AUTO_TEST_CASE(test_nsec3_nxqtype_ds)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;
  const unsigned int nbIterations = 10;
  addNSEC3UnhashedRecordToLW(DNSName("powerdns.com."), DNSName("powerdns.com."), "whatever", {QType::A}, 600, records, nbIterations);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(records.at(0).d_name, records.at(0).d_type)] = pair;
  records.clear();

  pdns::validation::ValidationContext validationContext;
  validationContext.d_nsec3IterationsRemainingQuota = 100U;
  /* this NSEC3 is not valid to deny the DS since it is from the child zone */
  BOOST_CHECK_EQUAL(getDenial(denialMap, DNSName("powerdns.com."), QType::DS, false, true, validationContext), dState::NODENIAL);
  /* the NSEC3 hash is not computed since we it is from the child zone */
  BOOST_CHECK_EQUAL(validationContext.d_nsec3IterationsRemainingQuota, 100U);
  /* AAAA should be fine, though */
  BOOST_CHECK_EQUAL(getDenial(denialMap, DNSName("powerdns.com."), QType::AAAA, false, true, validationContext), dState::NXQTYPE);
  BOOST_CHECK_EQUAL(validationContext.d_nsec3IterationsRemainingQuota, (100U - nbIterations));
}

BOOST_AUTO_TEST_CASE(test_nsec3_nxqtype_cname)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  addNSEC3UnhashedRecordToLW(DNSName("a.powerdns.com."), DNSName("powerdns.com."), "whatever", {QType::CNAME}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(records.at(0).d_name, records.at(0).d_type)] = pair;
  records.clear();

  /* this NSEC3 is not valid to deny a.powerdns.com|A since it states that a CNAME exists */
  dState denialState = getDenial(denialMap, DNSName("a.powerdns.com."), QType::A, false, true);
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);
}

BOOST_AUTO_TEST_CASE(test_nsec_nxdomain_denial_missing_wildcard)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  addNSECRecordToLW(DNSName("a.powerdns.com."), DNSName("d.powerdns.com"), {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(DNSName("a.powerdns.com."), QType::NSEC)] = pair;

  dState denialState = getDenial(denialMap, DNSName("b.powerdns.com."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);
}

BOOST_AUTO_TEST_CASE(test_nsec3_nxdomain_denial_missing_wildcard)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  addNSEC3NarrowRecordToLW(DNSName("a.powerdns.com."), DNSName("powerdns.com."), {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, records, 10);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  /* Add NSEC3 for the closest encloser */
  recordContents.clear();
  signatureContents.clear();
  records.clear();
  addNSEC3UnhashedRecordToLW(DNSName("powerdns.com."), DNSName("powerdns.com."), "whatever", {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, records, 10);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  dState denialState = getDenial(denialMap, DNSName("a.powerdns.com."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);
}

BOOST_AUTO_TEST_CASE(test_nsec_expanded_wildcard_proof)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("example.org."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  /* proves that a.example.com does exist, and has been generated from a wildcard (see the RRSIG below) */
  addNSECRecordToLW(DNSName("a.example.org."), DNSName("d.example.org"), {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("example.org."), 300, false, std::nullopt, DNSName("example.org."));
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(DNSName("a.example.org."), QType::NSEC)] = pair;

  /* This is an expanded wildcard proof, meaning that it does prove that the exact name
     does not exist so the wildcard can apply */
  dState denialState = getDenial(denialMap, DNSName("a.example.org."), QType(0).getCode(), false, false, std::nullopt, false, /* normally retrieved from the RRSIG's d_labels */ 2);
  BOOST_CHECK_EQUAL(denialState, dState::NXDOMAIN);
}

BOOST_AUTO_TEST_CASE(test_nsec_wildcard_with_cname)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("example.org."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  /* proves that b.example.com does not exist */
  addNSECRecordToLW(DNSName("a.example.org."), DNSName("d.example.org"), {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(DNSName("a.example.org."), QType::NSEC)] = pair;

  /* add a NSEC proving that a wildcard exists, without a CNAME type */
  recordContents.clear();
  signatureContents.clear();
  addNSECRecordToLW(DNSName("*.example.org."), DNSName("+.example.org"), {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::pair(DNSName("*.example.org."), QType::NSEC)] = pair;

  /* A does exist at the wildcard, AAAA does not */
  dState denialState = getDenial(denialMap, DNSName("b.example.org."), QType::A, false, true);
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);

  denialState = getDenial(denialMap, DNSName("b.example.org."), QType::AAAA, false, true);
  BOOST_CHECK_EQUAL(denialState, dState::NXQTYPE);

  /* now we replace the wildcard by one with a CNAME */
  recordContents.clear();
  signatureContents.clear();
  addNSECRecordToLW(DNSName("*.example.org."), DNSName("+.example.org"), {QType::CNAME, QType::RRSIG, QType::NSEC}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::pair(DNSName("*.example.org."), QType::NSEC)] = pair;

  /* A and AAAA do not exist but we have a CNAME so at the wildcard */
  denialState = getDenial(denialMap, DNSName("b.example.org."), QType::A, false, true);
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);

  denialState = getDenial(denialMap, DNSName("b.example.org."), QType::AAAA, false, true);
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);
}

BOOST_AUTO_TEST_CASE(test_nsec3_wildcard_with_cname)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("example.org."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  /* proves that b.example.com does not exist */
  addNSEC3NarrowRecordToLW(DNSName("b.example.org"), DNSName("example.org."), {QType::A, QType::TXT, QType::RRSIG, QType::NSEC3}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  /* Add NSEC3 for the closest encloser */
  recordContents.clear();
  signatureContents.clear();
  records.clear();
  addNSEC3UnhashedRecordToLW(DNSName("example.org."), DNSName("example.org."), "whatever", {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  /* add wildcard, without a CNAME type */
  recordContents.clear();
  signatureContents.clear();
  records.clear();
  addNSEC3UnhashedRecordToLW(DNSName("*.example.org."), DNSName("example.org"), "whatever", {QType::A, QType::TXT, QType::RRSIG, QType::NSEC3}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  /* A does exist at the wildcard, AAAA does not */
  dState denialState = getDenial(denialMap, DNSName("b.example.org."), QType::A, false, true);
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);

  denialState = getDenial(denialMap, DNSName("b.example.org."), QType::AAAA, false, true);
  BOOST_CHECK_EQUAL(denialState, dState::NXQTYPE);

  /* now we replace the wildcard by one with a CNAME */
  recordContents.clear();
  signatureContents.clear();
  records.clear();
  addNSEC3UnhashedRecordToLW(DNSName("*.example.org."), DNSName("example.org"), "whatever", {QType::CNAME, QType::RRSIG, QType::NSEC3}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  /* A and AAAA do not exist but we have a CNAME so at the wildcard */
  denialState = getDenial(denialMap, DNSName("b.example.org."), QType::A, false, true);
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);

  denialState = getDenial(denialMap, DNSName("b.example.org."), QType::AAAA, false, true);
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);
}

BOOST_AUTO_TEST_CASE(test_nsec_ent_denial)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  addNSECRecordToLW(DNSName("a.powerdns.com."), DNSName("a.c.powerdns.com."), {QType::A}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(DNSName("a.powerdns.com."), QType::NSEC)] = pair;

  /* this NSEC is valid to prove a NXQTYPE at c.powerdns.com because it proves that
     it is an ENT */
  dState denialState = getDenial(denialMap, DNSName("c.powerdns.com."), QType::AAAA, true, true);
  BOOST_CHECK_EQUAL(denialState, dState::NXQTYPE);

  /* this NSEC is not valid to prove a NXQTYPE at b.powerdns.com,
     it could prove a NXDOMAIN if it had an additional wildcard denial */
  denialState = getDenial(denialMap, DNSName("b.powerdns.com."), QType::AAAA, true, true);
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);

  /* this NSEC is not valid to prove a NXQTYPE for QType::A at a.c.powerdns.com either */
  denialState = getDenial(denialMap, DNSName("a.c.powerdns.com."), QType::A, true, true);
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);

  /* if we add the wildcard denial proof, we should get a NXDOMAIN proof for b.powerdns.com */
  recordContents.clear();
  signatureContents.clear();
  addNSECRecordToLW(DNSName(").powerdns.com."), DNSName("+.powerdns.com."), {}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();
  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::pair(DNSName(").powerdns.com."), QType::NSEC)] = pair;

  denialState = getDenial(denialMap, DNSName("b.powerdns.com."), QType::A, true, false);
  BOOST_CHECK_EQUAL(denialState, dState::NXDOMAIN);

  /* this NSEC is NOT valid to prove a NXDOMAIN at c.powerdns.com because it proves that
     it exists and is an ENT */
  denialState = getDenial(denialMap, DNSName("c.powerdns.com."), QType::AAAA, true, false);
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);
}

BOOST_AUTO_TEST_CASE(test_nsec_denial_invalid_signer)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("sub.powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  addNSECRecordToLW(DNSName("sub.powerdns.com."), DNSName("z.powerdns.com."), {QType::SOA, QType::A}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("sub.powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();
  addNSECRecordToLW(DNSName(").powerdns.com."), DNSName("+.powerdns.com."), {}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("powerdns.com."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));
  records.clear();

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(DNSName("sub.powerdns.com."), QType::NSEC)] = pair;

  /* this NSEC cannot prove that sub2 does not exist, because it is signed
     by the child side of sub.powerdns.com but tries to refute the existence
     of a name in the parent zone */
  dState denialState = getDenial(denialMap, DNSName("sub2.powerdns.com."), QType::A, false, false, std::nullopt);
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);
}

BOOST_AUTO_TEST_CASE(test_nsec3_denial_invalid_signer)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("example.org."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  generateKeyMaterial(DNSName("sub.example.org."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  /* proves that sub2.example.com does not exist */
  addNSEC3NarrowRecordToLW(DNSName("sub2.example.org"), DNSName("example.org."), {QType::A, QType::TXT, QType::RRSIG, QType::NSEC3}, 600, records);
  recordContents.insert(records.at(0).getContent());
  /* but is signed by a subzone */
  addRRSIG(keys, records, DNSName("sub.example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  /* Add NSEC3 for the closest encloser */
  recordContents.clear();
  signatureContents.clear();
  records.clear();
  addNSEC3UnhashedRecordToLW(DNSName("example.org."), DNSName("example.org."), "whatever", {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  /* add wildcard, without the type */
  recordContents.clear();
  signatureContents.clear();
  records.clear();
  addNSEC3UnhashedRecordToLW(DNSName("*.example.org."), DNSName("example.org"), "whatever", {QType::AAAA}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("example.org."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  dState denialState = getDenial(denialMap, DNSName("sub2.example.org."), QType::A, false, false);
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);
}

BOOST_AUTO_TEST_CASE(test_nsec3_ancestor_nxqtype_denial)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  /*
    The RRSIG from "." denies the existence of any type except NS at a.
    However since it's an ancestor delegation NSEC (NS bit set, SOA bit clear,
    signer field that is shorter than the owner name of the NSEC RR) it can't
    be used to deny anything except the whole name or a DS.
  */
  addNSEC3UnhashedRecordToLW(DNSName("a."), DNSName("."), "whatever", {QType::NS}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(records.at(0).d_name, records.at(0).d_type)] = pair;
  records.clear();

  /* RFC 6840 section 4.1 "Clarifications on Nonexistence Proofs":
     Ancestor delegation NSEC or NSEC3 RRs MUST NOT be used to assume
     nonexistence of any RRs below that zone cut, which include all RRs at
     that (original) owner name other than DS RRs, and all RRs below that
     owner name regardless of type.
  */

  dState denialState = getDenial(denialMap, DNSName("a."), QType::A, false, true);
  /* no denial means the qname/qtype is not denied, because an ancestor
     delegation NSEC3 can only deny the DS */
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);

  denialState = getDenial(denialMap, DNSName("a."), QType::DS, true, true);
  BOOST_CHECK_EQUAL(denialState, dState::NXQTYPE);

  /* it can not be used to deny any RRs below that owner name either */
  /* Add NSEC3 for the next closer */
  recordContents.clear();
  signatureContents.clear();
  records.clear();
  addNSEC3NarrowRecordToLW(DNSName("sub.a."), DNSName("."), {QType::A, QType::TXT, QType::RRSIG, QType::NSEC3}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  /* add wildcard denial */
  recordContents.clear();
  signatureContents.clear();
  records.clear();
  addNSEC3NarrowRecordToLW(DNSName("*.a."), DNSName("."), {QType::A, QType::TXT, QType::RRSIG, QType::NSEC3}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  denialState = getDenial(denialMap, DNSName("sub.a."), QType::A, false, true);
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);

  /* not even the DS! */
  denialState = getDenial(denialMap, DNSName("sub.a."), QType::DS, false, true);
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);
}

BOOST_AUTO_TEST_CASE(test_nsec3_denial_too_many_iterations)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  /* adding a NSEC3 with more iterations that we support */
  addNSEC3UnhashedRecordToLW(DNSName("a."), DNSName("."), "whatever", {QType::AAAA}, 600, records, g_maxNSEC3Iterations + 100);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(records.at(0).d_name, records.at(0).d_type)] = pair;
  records.clear();

  dState denialState = getDenial(denialMap, DNSName("a."), QType::A, false, true);
  /* since we refuse to compute more than g_maxNSEC3Iterations iterations, it should be Insecure */
  BOOST_CHECK_EQUAL(denialState, dState::INSECURE);
}

BOOST_AUTO_TEST_CASE(test_nsec3_many_labels_between_name_and_closest_encloser)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("powerdns.com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  ContentSigPair pair;
  cspmap_t denialMap;

  const DNSName requestedName("_ldap._tcp.a.b.c.d.powerdns.com.");
  const DNSName zone("powerdns.com.");
  /* Add NSEC3 for the closest encloser */
  recordContents.clear();
  signatureContents.clear();
  records.clear();
  addNSEC3UnhashedRecordToLW(DNSName("powerdns.com."), zone, "whatever", {QType::A, QType::TXT, QType::RRSIG, QType::NSEC}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, zone, 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  /* Add NSEC3 for the next closer */
  recordContents.clear();
  signatureContents.clear();
  records.clear();
  addNSEC3NarrowRecordToLW(DNSName("d.powerdns.com."), zone, {QType::A, QType::TXT, QType::RRSIG, QType::NSEC3}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, zone, 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  /* add wildcard denial */
  recordContents.clear();
  signatureContents.clear();
  records.clear();
  addNSEC3NarrowRecordToLW(DNSName("*.powerdns.com."), zone, {QType::A, QType::TXT, QType::RRSIG, QType::NSEC3}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, zone, 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  g_maxNSEC3sPerRecordToConsider = 10;
  auto denialState = getDenial(denialMap, requestedName, QType::A, false, true);
  g_maxNSEC3sPerRecordToConsider = 0;
  BOOST_CHECK_EQUAL(denialState, dState::NXDOMAIN);
}

BOOST_AUTO_TEST_CASE(test_nsec3_insecure_delegation_denial)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

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
  addNSEC3UnhashedRecordToLW(DNSName("a."), DNSName("."), "whatever", {}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(records.at(0).d_name, records.at(0).d_type)] = pair;
  records.clear();

  /* Insecure because the NS is not set, so while it does
     denies the DS, it can't prove an insecure delegation */
  dState denialState = getDenial(denialMap, DNSName("a."), QType::DS, true, true);
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);
}

BOOST_AUTO_TEST_CASE(test_nsec3_insecure_delegation_denial_soa)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  /*
   * RFC 5155 section 8.9:
   * If there is an NSEC3 RR present in the response that matches the
   * delegation name, then the validator MUST ensure that the NS bit is
   * set and that the DS bit is not set in the Type Bit Maps field of the
   * NSEC3 RR.
   */
  /*
    The RRSIG from "." denies the existence of any type at "a" except NS and SOA.
    NS has to be set since it is proving an insecure delegation, but SOA should NOT!
  */
  addNSEC3UnhashedRecordToLW(DNSName("a."), DNSName("."), "whatever", {QType::NS, QType::SOA}, 600, records);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(records.at(0).d_name, records.at(0).d_type)] = pair;
  records.clear();

  /* Insecure because both NS and SOA are set, so it is not a proper delegation */
  dState denialState = getDenial(denialMap, DNSName("a."), QType::DS, true, true);
  BOOST_CHECK_EQUAL(denialState, dState::NODENIAL);
}

BOOST_AUTO_TEST_CASE(test_nsec3_ent_opt_out)
{
  initSR();

  testkeysset_t keys;
  generateKeyMaterial(DNSName("."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);

  vector<DNSRecord> records;

  sortedRecords_t recordContents;
  vector<shared_ptr<const RRSIGRecordContent>> signatureContents;

  /*
   * RFC 7129 section 5.1:
   * A recently discovered corner case (see RFC Errata ID 3441 [Err3441])
   * shows that not only those delegations remain insecure but also the
   * empty non-terminal space that is derived from those delegations.
   */
  /*
    We have a NSEC3 proving that was.here does exist, and a second
    one proving that ent.was.here. does not,
    There NSEC3 are opt-out, so the result should be insecure (and we don't need
    a wildcard proof).
  */
  addNSEC3UnhashedRecordToLW(DNSName("was.here."), DNSName("."), "whatever", {}, 600, records, 10, true /* opt out */);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  ContentSigPair pair;
  pair.records = recordContents;
  pair.signatures = signatureContents;
  cspmap_t denialMap;
  denialMap[std::pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  /* it can not be used to deny any RRs below that owner name either */
  /* Add NSEC3 for the next closer */
  recordContents.clear();
  signatureContents.clear();
  records.clear();
  addNSEC3NarrowRecordToLW(DNSName("ent.was.here."), DNSName("."), {QType::RRSIG, QType::NSEC3}, 600, records, 10, true /* opt-out */);
  recordContents.insert(records.at(0).getContent());
  addRRSIG(keys, records, DNSName("."), 300);
  signatureContents.push_back(getRR<RRSIGRecordContent>(records.at(1)));

  pair.records = recordContents;
  pair.signatures = signatureContents;
  denialMap[std::pair(records.at(0).d_name, records.at(0).d_type)] = pair;

  /* Insecure because the opt-out bit is set */
  dState denialState = getDenial(denialMap, DNSName("ent.was.here."), QType::A, false, true);
  BOOST_CHECK_EQUAL(denialState, dState::OPTOUT);
}

BOOST_AUTO_TEST_CASE(test_dnssec_rrsig_negcache_validity)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;
  const time_t fixedNow = sr->getNow().tv_sec;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, std::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    DNSName auth = domain;
    auth.chopOff();

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
    }
    {
      setLWResult(res, RCode::NoError, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 3600);
      addRRSIG(keys, res->d_records, domain, 300);
      addNSECRecordToLW(domain, DNSName("z."), {QType::NSEC, QType::RRSIG}, 600, res->d_records);
      addRRSIG(keys, res->d_records, domain, 1, false, std::nullopt, std::nullopt, fixedNow);
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* check that the entry has not been negatively cached for longer than the RRSIG validity */
  NegCache::NegCacheEntry ne;
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);
  BOOST_REQUIRE_EQUAL(g_negCache->get(target, QType(QType::A), sr->getNow(), ne), true);
  BOOST_CHECK_EQUAL(ne.d_ttd, fixedNow + 1);
  BOOST_CHECK_EQUAL(ne.d_validationState, vState::Secure);
  BOOST_CHECK_EQUAL(ne.authoritySOA.records.size(), 1U);
  BOOST_CHECK_EQUAL(ne.authoritySOA.signatures.size(), 1U);
  BOOST_CHECK_EQUAL(ne.DNSSECRecords.records.size(), 1U);
  BOOST_CHECK_EQUAL(ne.DNSSECRecords.signatures.size(), 1U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_rrsig_negcache_bogus_validity)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;
  const time_t fixedNow = sr->getNow().tv_sec;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, std::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    DNSName auth = domain;
    auth.chopOff();

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
    }
    {
      setLWResult(res, RCode::NoError, true, false, true);
      addRecordToLW(res, domain, QType::SOA, "pdns-public-ns1.powerdns.com. pieter\\.lexis.powerdns.com. 2017032301 10800 3600 604800 3600", DNSResourceRecord::AUTHORITY, 86400);
      addRRSIG(keys, res->d_records, domain, 86400);
      addNSECRecordToLW(domain, DNSName("z."), {QType::NSEC, QType::RRSIG}, 86400, res->d_records);
      /* no RRSIG */
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  SyncRes::s_maxnegttl = 3600;
  SyncRes::s_maxbogusttl = 360;

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* check that the entry has been negatively cached but not longer than s_maxbogusttl */
  NegCache::NegCacheEntry ne;
  BOOST_CHECK_EQUAL(g_negCache->size(), 1U);
  BOOST_REQUIRE_EQUAL(g_negCache->get(target, QType(QType::A), sr->getNow(), ne), true);
  BOOST_CHECK_EQUAL(ne.d_ttd, fixedNow + SyncRes::s_maxbogusttl);
  BOOST_CHECK_EQUAL(ne.d_validationState, vState::BogusNoRRSIG);
  BOOST_CHECK_EQUAL(ne.authoritySOA.records.size(), 1U);
  BOOST_CHECK_EQUAL(ne.authoritySOA.signatures.size(), 1U);
  BOOST_CHECK_EQUAL(ne.DNSSECRecords.records.size(), 1U);
  BOOST_CHECK_EQUAL(ne.DNSSECRecords.signatures.size(), 0U);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 3U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_rrsig_cache_validity)
{
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::ValidateAll);

  primeHints();
  const DNSName target("com.");
  const ComboAddress targetAddr("192.0.2.42");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  generateKeyMaterial(DNSName("com."), DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;
  const time_t tnow = sr->getNow().tv_sec;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, std::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    DNSName auth = domain;
    auth.chopOff();

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, auth, type, keys);
    }
    {
      setLWResult(res, RCode::NoError, true, false, true);
      addRecordToLW(res, domain, QType::A, targetAddr.toString(), DNSResourceRecord::ANSWER, 3600);
      addRRSIG(keys, res->d_records, domain, 1, false, std::nullopt, std::nullopt, tnow);
      return LWResult::Result::Success;
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);

  /* check that the entry has not been cached for longer than the RRSIG validity */
  const ComboAddress who;
  vector<DNSRecord> cached;
  MemRecursorCache::SigRecs signatures;
  BOOST_REQUIRE_EQUAL(g_recCache->get(tnow, target, QType(QType::A), MemRecursorCache::RequireAuth, &cached, who, std::nullopt, &signatures), 1);
  BOOST_REQUIRE_EQUAL(cached.size(), 1U);
  BOOST_REQUIRE_EQUAL(signatures->size(), 1U);
  BOOST_CHECK_EQUAL((cached[0].d_ttl - tnow), 1);

  /* again, to test the cache */
  ret.clear();
  res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  BOOST_CHECK_EQUAL(queriesCount, 4U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_cache_secure)
{
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
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, std::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
    }
    {
      if (domain == target && type == QType::A) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, target, QType::A, "192.0.2.1");
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Indeterminate);
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
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::A || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 2U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_cache_insecure)
{
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

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, std::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
    }
    {
      if (domain == target && type == QType::A) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, target, QType::A, "192.0.2.1");
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Indeterminate);
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
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Insecure);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::A);
  }
  BOOST_CHECK_EQUAL(queriesCount, 1U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_cache_bogus)
{
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
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, std::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
    }
    {
      if (domain == target && type == QType::A) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, target, QType::A, "192.0.2.1", DNSResourceRecord::ANSWER, 86400);
        /* no RRSIG */
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  SyncRes::s_maxbogusttl = 3600;

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Indeterminate);
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
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
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
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::BogusNoRRSIG);
  BOOST_REQUIRE_EQUAL(ret.size(), 1U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::A);
    BOOST_CHECK_EQUAL(record.d_ttl, SyncRes::s_maxbogusttl);
  }
  BOOST_CHECK_EQUAL(queriesCount, 3U);
}

BOOST_AUTO_TEST_CASE(test_dnssec_validation_from_cache_secure_any)
{
  /*
    Validation is optional, and the first two queries (A, AAAA) do not ask for it,
    so the answer are cached as Indeterminate.
    The third query asks for validation, and is for ANY, so the answer should be marked as
    Secure, after just-in-time validation.
    The last query also requests validation but is for AAAA only.
  */
  std::unique_ptr<SyncRes> sr;
  initSR(sr, true);

  setDNSSECValidation(sr, DNSSECMode::Process);

  primeHints();
  const DNSName target("com.");
  testkeysset_t keys;

  auto luaconfsCopy = g_luaconfs.getCopy();
  luaconfsCopy.dsAnchors.clear();
  generateKeyMaterial(g_rootdnsname, DNSSEC::ECDSA256, DNSSEC::DIGEST_SHA256, keys, luaconfsCopy.dsAnchors);
  g_luaconfs.setState(luaconfsCopy);

  size_t queriesCount = 0;

  sr->setAsyncCallback([&](const ComboAddress& /* ip */, const DNSName& domain, int type, bool /* doTCP */, bool /* sendRDQuery */, int /* EDNS0Level */, struct timeval* /* now */, std::optional<Netmask>& /* srcmask */, const ResolveContext& /* context */, LWResult* res, bool* /* chained */) {
    queriesCount++;

    if (type == QType::DS || type == QType::DNSKEY) {
      return genericDSAndDNSKEYHandler(res, domain, domain, type, keys, false);
    }
    {
      if (domain == target && type == QType::A) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, target, QType::A, "192.0.2.1");
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        return LWResult::Result::Success;
      }
      if (domain == target && type == QType::AAAA) {
        setLWResult(res, 0, true, false, true);
        addRecordToLW(res, target, QType::AAAA, "2001:db8::1");
        addRRSIG(keys, res->d_records, DNSName("."), 300);
        return LWResult::Result::Success;
      }
    }

    return LWResult::Result::Timeout;
  });

  vector<DNSRecord> ret;
  /* first query does not require validation */
  sr->setDNSSECValidationRequested(false);
  int res = sr->beginResolve(target, QType(QType::A), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::A || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 1U);

  ret.clear();
  /* second query does not require validation either */
  sr->setDNSSECValidationRequested(false);
  res = sr->beginResolve(target, QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Indeterminate);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::AAAA || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  ret.clear();
  /* third one _does_ require validation */
  sr->setDNSSECValidationRequested(true);
  MemRecursorCache::s_maxRRSetSize = 1;
  BOOST_CHECK_THROW(sr->beginResolve(target, QType(QType::ANY), QClass::IN, ret), ImmediateServFailException);
  // BOOST_CHECK_EQUAL(res, RCode::NoError);
  // BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  // BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  // for (const auto& record : ret) {
  //   BOOST_CHECK(record.d_type == QType::A || record.d_type == QType::AAAA || record.d_type == QType::RRSIG);
  // }
  BOOST_CHECK_EQUAL(queriesCount, 2U);

  ret.clear();
  /* next one _does_ require validation */
  MemRecursorCache::s_limitQTypeAny = false;
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::ANY), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 4U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::A || record.d_type == QType::AAAA || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 3U);

  ret.clear();
  /* last one also requires validation */
  sr->setDNSSECValidationRequested(true);
  res = sr->beginResolve(target, QType(QType::AAAA), QClass::IN, ret);
  BOOST_CHECK_EQUAL(res, RCode::NoError);
  BOOST_CHECK_EQUAL(sr->getValidationState(), vState::Secure);
  BOOST_REQUIRE_EQUAL(ret.size(), 2U);
  for (const auto& record : ret) {
    BOOST_CHECK(record.d_type == QType::AAAA || record.d_type == QType::RRSIG);
  }
  BOOST_CHECK_EQUAL(queriesCount, 3U);
}

BOOST_AUTO_TEST_SUITE_END()
