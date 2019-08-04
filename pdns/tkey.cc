#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "packethandler.hh"

void PacketHandler::tkeyHandler(const DNSPacket& p, std::unique_ptr<DNSPacket>& r) {
  TKEYRecordContent tkey_in;
  std::shared_ptr<TKEYRecordContent> tkey_out(new TKEYRecordContent());
  DNSName name;
  bool sign = false;

  if (!p.getTKEYRecord(&tkey_in, &name)) {
    g_log<<Logger::Error<<"TKEY request but no TKEY RR found"<<endl;
    r->setRcode(RCode::FormErr);
    return;
  }

  // retain original name for response
  tkey_out->d_error = 0;
  tkey_out->d_mode = tkey_in.d_mode;
  tkey_out->d_algo = tkey_in.d_algo;
  tkey_out->d_inception = time((time_t*)NULL);
  tkey_out->d_expiration = tkey_out->d_inception+15;

  GssContext ctx(name);

  if (tkey_in.d_mode == 3) { // establish context
    if (tkey_in.d_algo == DNSName("gss-tsig.")) {
      std::vector<std::string> meta;
      DNSName tmpName(name);
      do {
        if (B.getDomainMetadata(tmpName, "GSS-ACCEPTOR-PRINCIPAL", meta) && meta.size()>0) {
          break;
        }
      } while(tmpName.chopOff());

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
    if (p.d_havetsig == false) { // unauthenticated
      if (p.d.opcode == Opcode::Update)
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
  r->addRecord(zrr);

  if (sign)
  {
    TSIGRecordContent trc;
    trc.d_algoName = DNSName("gss-tsig");
    trc.d_time = tkey_out->d_inception;
    trc.d_fudge = 300;
    trc.d_mac = "";
    trc.d_origID = p.d.id;
    trc.d_eRcode = 0;
    trc.d_otherData = "";
    // this should cause it to lookup name context
    r->setTSIGDetails(trc, name, name.toStringNoDot(), "", false);
  }

  r->commitD();
}
