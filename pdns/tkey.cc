#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "packethandler.hh"

void PacketHandler::tkeyHandler(const DNSPacket& p, std::unique_ptr<DNSPacket>& r) {
  TKEYRecordContent tkey_in;
  std::shared_ptr<TKEYRecordContent> tkey_out(new TKEYRecordContent());
  DNSName name;

  if (!p.getTKEYRecord(&tkey_in, &name)) {
    g_log<<Logger::Error<<"TKEY request but no TKEY RR found"<<endl;
    r->setRcode(RCode::FormErr);
    return;
  }

  // retain original name for response
  tkey_out->d_error = 0;
  tkey_out->d_mode = tkey_in.d_mode;
  tkey_out->d_algo = tkey_in.d_algo;
  tkey_out->d_inception = time((time_t*)nullptr);
  tkey_out->d_expiration = tkey_out->d_inception+15;

  if (tkey_in.d_mode == 3) { // establish context
    if (tkey_in.d_algo == DNSName("gss-tsig.")) {
      tkey_out->d_error = 19;
    } else {
      tkey_out->d_error = 21; // BADALGO
    }
  } else if (tkey_in.d_mode == 5) { // destroy context
    if (p.d_havetsig == false) { // unauthenticated
      if (p.d.opcode == Opcode::Update)
        r->setRcode(RCode::Refused);
      else
        r->setRcode(RCode::NotAuth);
      return;
    }

    tkey_out->d_error = 20; // BADNAME (because we have no support for anything here)
  } else {
    if (p.d_havetsig == false && tkey_in.d_mode != 2) { // unauthenticated
      if (p.d.opcode == Opcode::Update)
        r->setRcode(RCode::Refused);
      else
        r->setRcode(RCode::NotAuth);
      return;
    }
    tkey_out->d_error = 19; // BADMODE
  }

  tkey_out->d_keysize = tkey_out->d_key.size();
  tkey_out->d_othersize = tkey_out->d_other.size();

  DNSZoneRecord zrr;

  zrr.dr.d_name = name;
  zrr.dr.d_ttl = 0;
  zrr.dr.d_type = QType::TKEY;
  zrr.dr.d_class = QClass::ANY;
  zrr.dr.d_content = tkey_out;
  zrr.dr.d_place = DNSResourceRecord::ANSWER;
  r->addRecord(std::move(zrr));
  r->commitD();
}
