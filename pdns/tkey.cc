#include "config.h"
#include "namespaces.hh"
#include "dns.hh"
#include "dnsparser.hh"
#include "dnspacket.hh"
#include "dnsrecords.hh"
#include "tkey.hh"
#include "logger.hh"
#include <boost/foreach.hpp>
#include <boost/shared_ptr.hpp>

using namespace std;

void pdns_tkey_handler(DNSPacket *p, DNSPacket *r) {
  TKEYRecordContent tkey_in;
  boost::shared_ptr<TKEYRecordContent> tkey_out(new TKEYRecordContent());
  string label;
  bool sign=false;

  if (!p->getTKEYRecord(&tkey_in, &label)) {
    L<<Logger::Error<<"TKEY request but no TKEY RR found"<<endl;
    r->setRcode(RCode::FormErr);
    return;
  }

  label = toLowerCanonic(label);

  tkey_out->d_error = 0;
  tkey_out->d_mode = tkey_in.d_mode;
  tkey_out->d_algo = tkey_in.d_algo;
  tkey_out->d_inception = time((time_t*)NULL);
  tkey_out->d_expiration = tkey_out->d_inception+15;

  if (tkey_in.d_mode == 3) {
#ifdef ENABLE_GSS_TSIG
    if (tkey_in.d_algo != "gss-tsig.") { 
      L<<Logger::Error<<"TKEY algorithm " << tkey_in.d_algo << " unsupported" <<endl;
      tkey_out->d_error = 21; // BADALG
    } else {
      int result = pdns_gssapi_accept_ctx(label, tkey_in.d_key, tkey_out->d_key);
      if (result == PDNS_GSSAPI_OK) { // complete
        sign=true;
      } else if (result == PDNS_GSSAPI_CONTINUE) { // continue
        sign=false;
      } else if (result == PDNS_GSSAPI_BADNAME) { 
        tkey_out->d_error = 20; // BADNAME
      } else if (result == PDNS_GSSAPI_BADKEY) { 
        tkey_out->d_error = 17; // BADKEY
      }
    }
#else
    tkey_out->d_error = 19; // BADMODE
#endif
  } else if (tkey_in.d_mode == 5) {
    if (p->d_havetsig == false) { // unauthenticated
      if (p->d.opcode == Opcode::Update)
        r->setRcode(RCode::Refused);
      else
        r->setRcode(RCode::NotAuth);
      return;
    }
    // remove context
#ifdef ENABLE_GSS_TSIG
    if (!pdns_gssapi_delete_ctx(label, tkey_in.d_key, tkey_out->d_key)) {
      tkey_out->d_error = 20; // BADNAME
    }
#else
    // sorry, return failure
    tkey_out->d_error = 20; // BADNAME (because we have no support for anything here)
#endif
  } else {
    if (p->d_havetsig == false && tkey_in.d_mode != 2) { // unauthenticated
      if (p->d.opcode == Opcode::Update)
        r->setRcode(RCode::Refused);
      else
        r->setRcode(RCode::NotAuth);
      return;
    }
    tkey_out->d_error = 19; // BADMODE
  }

  tkey_out->d_keysize = tkey_out->d_key.size();
  tkey_out->d_othersize = tkey_out->d_other.size();

  DNSRecord rec;
  rec.d_label = label;
  rec.d_ttl = 0;
  rec.d_type = QType::TKEY;
  rec.d_class = QClass::ANY;
  rec.d_content = tkey_out;
  DNSResourceRecord rr(rec);
  rr.qclass = QClass::ANY;
  rr.d_place = DNSResourceRecord::ANSWER;
  r->addRecord(rr);
#ifdef ENABLE_GSS_TSIG
  if (sign) 
  {
    TSIGRecordContent trc;
    trc.d_algoName = "gss-tsig";
    trc.d_time = tkey_out->d_inception;
    trc.d_fudge = 300;
    trc.d_mac = "";
    trc.d_origID = p->d.id;
    trc.d_eRcode = 0;
    trc.d_otherData = "";
    // this should cause it to lookup label context
    r->setTSIGDetails(trc, label, label, "", false);
  }
#endif
  r->commitD();
}
