#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "packethandler.hh"

void PacketHandler::tkeyHandler(DNSPacket *p, DNSPacket *r) {
  TKEYRecordContent tkey_in;
  std::shared_ptr<TKEYRecordContent> tkey_out(new TKEYRecordContent());
  DNSName label;
  bool sign = false;

  if (!p->getTKEYRecord(&tkey_in, &label)) {
    L<<Logger::Error<<"TKEY request but no TKEY RR found"<<endl;
    r->setRcode(RCode::FormErr);
    return;
  }

  // retain original label for response
  tkey_out->d_error = 0;
  tkey_out->d_mode = tkey_in.d_mode;
  tkey_out->d_algo = tkey_in.d_algo;
  tkey_out->d_inception = time((time_t*)NULL);
  tkey_out->d_expiration = tkey_out->d_inception+15;

  GssContext ctx(label.toStringNoDot());

  if (tkey_in.d_mode == 3) { // establish context
    if (tkey_in.d_algo == "gss-tsig.") {
      std::vector<std::string> meta;
      DNSName tmpLabel(label);
      do {
        if (B.getDomainMetadata(tmpLabel, "GSS-ACCEPTOR-PRINCIPAL", meta) && meta.size()>0) {
          break;
        }
      } while(tmpLabel.chopOff());

      if (meta.size()>0) {
        ctx.setLocalPrincipal(meta[0]);
      }
      // try to get a context
      if (!ctx.accept(tkey_in.d_key, tkey_out->d_key))
        tkey_out->d_error = 19;
      else
        sign = true;
    } else {
      tkey_out->d_error = 21; // BADALGO
    }
  } else if (tkey_in.d_mode == 5) { // destroy context
    if (p->d_havetsig == false) { // unauthenticated
      if (p->d.opcode == Opcode::Update)
        r->setRcode(RCode::Refused);
      else
        r->setRcode(RCode::NotAuth);
      return;
    }
    if (ctx.valid())
      ctx.destroy();
    else
      tkey_out->d_error = 20; // BADNAME (because we have no support for anything here)
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
  rr.qtype = QType::TKEY;
  rr.d_place = DNSResourceRecord::ANSWER;
  r->addRecord(rr);

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
    r->setTSIGDetails(trc, label, label.toStringNoDot(), "", false);
  }

  r->commitD();
}
