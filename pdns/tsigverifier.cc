
#include "tsigverifier.hh"
#include "dnssecinfra.hh"
#include "gss_context.hh"

bool TSIGTCPVerifier::check(const string& data, const MOADNSParser& mdp)
{
  if(d_tt.name.empty()) { // TSIG verify message
    return true;
  }

  string theirMac;
  bool checkTSIG = false;
  // If we have multiple messages, we need to concatenate them together. We also need to make sure we know the location of
  // the TSIG record so we can remove it in makeTSIGMessageFromTSIGPacket
  d_signData.append(data);
  if (mdp.getTSIGPos() == 0) {
    d_tsigPos += data.size();
  }
  else {
    d_tsigPos += mdp.getTSIGPos();
  }

  for(const auto& answer :  mdp.d_answers) {
    if (answer.first.d_type == QType::SOA) {
      // A SOA is either the first or the last record. We need to check TSIG if that's the case.
      checkTSIG = true;
    }

    if(answer.first.d_type == QType::TSIG) {
      shared_ptr<TSIGRecordContent> trc = getRR<TSIGRecordContent>(answer.first);
      if(trc) {
        theirMac = trc->d_mac;
        d_trc.d_time = trc->d_time;
        d_trc.d_fudge = trc->d_fudge;
        checkTSIG = true;
      }
    }
  }

  if(!checkTSIG && d_nonSignedMessages > 99) { // We're allowed to get 100 digest without a TSIG.
    throw std::runtime_error("No TSIG message received in last 100 messages of AXFR transfer.");
  }

  if (checkTSIG) {
    if (theirMac.empty()) {
      throw std::runtime_error("No TSIG on AXFR response from "+d_remote.toStringWithPort()+" , should be signed with TSIG key '"+d_tt.name.toString()+"'");
    }

    uint64_t delta = std::abs((int64_t)d_trc.d_time - (int64_t)time(nullptr));
    if(delta > d_trc.d_fudge) {
      throw std::runtime_error("Invalid TSIG time delta " + std::to_string(delta) + " >  fudge " + std::to_string(d_trc.d_fudge));
    }
    string message;
    if (!d_prevMac.empty()) {
      message = makeTSIGMessageFromTSIGPacket(d_signData, d_tsigPos, d_tt.name, d_trc, d_prevMac, true, d_signData.size()-data.size());
    } else {
      message = makeTSIGMessageFromTSIGPacket(d_signData, d_tsigPos, d_tt.name, d_trc, d_trc.d_mac, false);
    }

    TSIGHashEnum algo;
    if (!getTSIGHashEnum(d_trc.d_algoName, algo)) {
      throw std::runtime_error("Unsupported TSIG HMAC algorithm " + d_trc.d_algoName.toString());
    }

    if (algo == TSIG_GSS) {
      GssContext gssctx(d_tt.name);
      if (!gss_verify_signature(d_tt.name, message, theirMac)) {
        throw std::runtime_error("Signature failed to validate on AXFR response from "+d_remote.toStringWithPort()+" signed with TSIG key '"+d_tt.name.toString()+"'");
      }
    } else {
      string ourMac=calculateHMAC(d_tt.secret, message, algo);

      if(!constantTimeStringEquals(ourMac, theirMac)) {
        throw std::runtime_error("Signature failed to validate on AXFR response from "+d_remote.toStringWithPort()+" signed with TSIG key '"+d_tt.name.toString()+"'");
      }
    }

    // Reset and store some values for the next chunks.
    d_prevMac = theirMac;
    d_nonSignedMessages = 0;
    d_signData.clear();
    d_tsigPos = 0;
  }
  else
    d_nonSignedMessages++;

  return true;
}
