/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dnsrecords.hh"

class NSECBitmapGenerator
{
public:
  NSECBitmapGenerator(DNSPacketWriter& pw_): pw(pw_)
  {
    memset(res, 0, sizeof(res));
  }

  void set(uint16_t type)
  {
    uint16_t bit = type % 256;
    int window = static_cast<int>(type / 256);

    if (window != oldWindow) {
      if (oldWindow > -1) {
        res[0] = static_cast<unsigned char>(oldWindow);
        res[1] = static_cast<unsigned char>(len);
        tmp.assign(res, res+len+2);
        pw.xfrBlob(tmp);
      }
      memset(res, 0, sizeof(res));
      oldWindow = window;
    }
    res[2+bit/8] |= 1 << (7-(bit%8));
    len=1+bit/8;
  }

  void finish()
  {
    res[0] = static_cast<unsigned char>(oldWindow);
    res[1] = static_cast<unsigned char>(len);
    if (len) {
      tmp.assign(res, res+len+2);
      pw.xfrBlob(tmp);
    }
  }

private:
  DNSPacketWriter& pw;
  /* one byte for the window,
     one for the length,
     then the maximum of 32 bytes */
  uint8_t res[34];
  int oldWindow{-1};
  int len{0};
  string tmp;
};

void NSECBitmap::toPacket(DNSPacketWriter& pw) const
{
  NSECBitmapGenerator nbg(pw);
  if (d_bitset) {
    size_t found = 0;
    size_t l_count = d_bitset->count();
    for(size_t idx = 0; idx < nbTypes && found < l_count; ++idx){
      if (!d_bitset->test(idx)) {
        continue;
      }
      found++;
      nbg.set(idx);
    }
  }
  else {
    for (const auto& type : d_set) {
      nbg.set(type);
    }
  }

  nbg.finish();
}

void NSECBitmap::fromPacket(PacketReader& pr)
{
  string bitmap;
  pr.xfrBlob(bitmap);

  // 00 06 20 00 00 00 00 03  -> NS RRSIG NSEC  ( 2, 46, 47 ) counts from left
  if(bitmap.empty()) {
    return;
  }

  if(bitmap.size() < 2) {
    throw MOADNSException("NSEC record with impossibly small bitmap");
  }

  for(unsigned int n = 0; n+1 < bitmap.size();) {
    uint8_t window=static_cast<uint8_t>(bitmap[n++]);
    uint8_t blen=static_cast<uint8_t>(bitmap[n++]);

    // end if zero padding and ensure packet length
    if (window == 0 && blen == 0) {
      break;
    }

    if (blen > 32) {
      throw MOADNSException("NSEC record with invalid bitmap length");
    }

    if (n + blen > bitmap.size()) {
      throw MOADNSException("NSEC record with bitmap length > packet length");
    }

    for(unsigned int k=0; k < blen; k++) {
      uint8_t val=bitmap[n++];
      for(int bit = 0; bit < 8 ; ++bit , val>>=1) {
        if(val & 1) {
          set((7-bit) + 8*(k) + 256*window);
        }
      }
    }
  }
}

string NSECBitmap::getZoneRepresentation() const
{
  string ret;

  if (d_bitset) {
    size_t found = 0;
    size_t l_count = d_bitset->count();
    for(size_t idx = 0; idx < nbTypes && found < l_count; ++idx) {
      if (!d_bitset->test(idx)) {
        continue;
      }
      found++;

      ret+=" ";
      ret+=DNSRecordContent::NumberToType(idx);
    }
  }
  else {
    for(const auto& type : d_set) {
      ret+=" ";
      ret+=DNSRecordContent::NumberToType(type);
    }
  }

  return ret;
}

void NSECRecordContent::report()
{
  regist(1, 47, &make, &make, "NSEC");
}

std::shared_ptr<DNSRecordContent> NSECRecordContent::make(const string& content)
{
  return std::make_shared<NSECRecordContent>(content);
}

NSECRecordContent::NSECRecordContent(const string& content, const DNSName& zone)
{
  RecordTextReader rtr(content, zone);
  rtr.xfrName(d_next);

  while(!rtr.eof()) {
    uint16_t type;
    rtr.xfrType(type);
    set(type);
  }
}

void NSECRecordContent::toPacket(DNSPacketWriter& pw) const
{
  pw.xfrName(d_next);
  d_bitmap.toPacket(pw);
}

std::shared_ptr<NSECRecordContent::DNSRecordContent> NSECRecordContent::make(const DNSRecord & /* dr */, PacketReader& pr)
{
  auto ret=std::make_shared<NSECRecordContent>();
  pr.xfrName(ret->d_next);

  ret->d_bitmap.fromPacket(pr);

  return ret;
}

string NSECRecordContent::getZoneRepresentation(bool /* noDot */) const
{
  string ret;
  RecordTextWriter rtw(ret);
  rtw.xfrName(d_next);

  return ret + d_bitmap.getZoneRepresentation();
}

////// begin of NSEC3

void NSEC3RecordContent::report()
{
  regist(1, 50, &make, &make, "NSEC3");
}

std::shared_ptr<DNSRecordContent> NSEC3RecordContent::make(const string& content)
{
  return std::make_shared<NSEC3RecordContent>(content);
}

NSEC3RecordContent::NSEC3RecordContent(const string& content, const DNSName& zone)
{
  RecordTextReader rtr(content, zone);
  rtr.xfr8BitInt(d_algorithm);
  rtr.xfr8BitInt(d_flags);
  rtr.xfr16BitInt(d_iterations);

  rtr.xfrHexBlob(d_salt);
  rtr.xfrBase32HexBlob(d_nexthash);

  while(!rtr.eof()) {
    uint16_t type;
    rtr.xfrType(type);
    set(type);
  }
}

void NSEC3RecordContent::toPacket(DNSPacketWriter& pw) const
{
  pw.xfr8BitInt(d_algorithm);
  pw.xfr8BitInt(d_flags);
  pw.xfr16BitInt(d_iterations);
  pw.xfr8BitInt(d_salt.length());
  pw.xfrBlob(d_salt);

  pw.xfr8BitInt(d_nexthash.length());
  pw.xfrBlob(d_nexthash);

  d_bitmap.toPacket(pw);
}

std::shared_ptr<NSEC3RecordContent::DNSRecordContent> NSEC3RecordContent::make(const DNSRecord& /* dr */, PacketReader& pr)
{
  auto ret=std::make_shared<NSEC3RecordContent>();
  pr.xfr8BitInt(ret->d_algorithm);
  pr.xfr8BitInt(ret->d_flags);
  pr.xfr16BitInt(ret->d_iterations);
  uint8_t len;
  pr.xfr8BitInt(len);
  pr.xfrBlob(ret->d_salt, len);

  pr.xfr8BitInt(len);
  pr.xfrBlob(ret->d_nexthash, len);

  ret->d_bitmap.fromPacket(pr);
  return ret;
}

string NSEC3RecordContent::getZoneRepresentation(bool /* noDot */) const
{
  string ret;
  RecordTextWriter rtw(ret);
  rtw.xfr8BitInt(d_algorithm);
  rtw.xfr8BitInt(d_flags);
  rtw.xfr16BitInt(d_iterations);

  rtw.xfrHexBlob(d_salt);
  rtw.xfrBase32HexBlob(d_nexthash);

  return ret + d_bitmap.getZoneRepresentation();
}


void NSEC3PARAMRecordContent::report()
{
  regist(1, 51, &make, &make, "NSEC3PARAM");
  regist(254, 51, &make, &make, "NSEC3PARAM");
}

std::shared_ptr<DNSRecordContent> NSEC3PARAMRecordContent::make(const string& content)
{
  return std::make_shared<NSEC3PARAMRecordContent>(content);
}

NSEC3PARAMRecordContent::NSEC3PARAMRecordContent(const string& content, const DNSName& zone)
{
  RecordTextReader rtr(content, zone);
  rtr.xfr8BitInt(d_algorithm);
  rtr.xfr8BitInt(d_flags);
  rtr.xfr16BitInt(d_iterations);
  rtr.xfrHexBlob(d_salt);
}

void NSEC3PARAMRecordContent::toPacket(DNSPacketWriter& pw) const
{
  pw.xfr8BitInt(d_algorithm);
        pw.xfr8BitInt(d_flags);
        pw.xfr16BitInt(d_iterations);
  pw.xfr8BitInt(d_salt.length());
  // cerr<<"salt: '"<<makeHexDump(d_salt)<<"', "<<d_salt.length()<<endl;
  pw.xfrBlob(d_salt);
}

std::shared_ptr<NSEC3PARAMRecordContent::DNSRecordContent> NSEC3PARAMRecordContent::make(const DNSRecord& /* dr */, PacketReader& pr)
{
  auto ret=std::make_shared<NSEC3PARAMRecordContent>();
  pr.xfr8BitInt(ret->d_algorithm);
        pr.xfr8BitInt(ret->d_flags);
        pr.xfr16BitInt(ret->d_iterations);
  uint8_t len;
  pr.xfr8BitInt(len);
  pr.xfrHexBlob(ret->d_salt, len);
  return ret;
}

string NSEC3PARAMRecordContent::getZoneRepresentation(bool /* noDot */) const
{
  string ret;
  RecordTextWriter rtw(ret);
  rtw.xfr8BitInt(d_algorithm);
        rtw.xfr8BitInt(d_flags);
        rtw.xfr16BitInt(d_iterations);
  rtw.xfrHexBlob(d_salt);
  return ret;
}

////// end of NSEC3

////// begin of CSYNC

void CSYNCRecordContent::report()
{
  regist(1, 62, &make, &make, "CSYNC");
}

std::shared_ptr<DNSRecordContent> CSYNCRecordContent::make(const string& content)
{
  return std::make_shared<CSYNCRecordContent>(content);
}

CSYNCRecordContent::CSYNCRecordContent(const string& content, const DNSName& zone)
{
  RecordTextReader rtr(content, zone);
  rtr.xfr32BitInt(d_serial);
  rtr.xfr16BitInt(d_flags);

  while(!rtr.eof()) {
    uint16_t type;
    rtr.xfrType(type);
    set(type);
  }
}

void CSYNCRecordContent::toPacket(DNSPacketWriter& pw) const
{
  pw.xfr32BitInt(d_serial);
  pw.xfr16BitInt(d_flags);

  d_bitmap.toPacket(pw);
}

std::shared_ptr<CSYNCRecordContent::DNSRecordContent> CSYNCRecordContent::make(const DNSRecord& /* dr */, PacketReader& pr)
{
  auto ret=std::make_shared<CSYNCRecordContent>();
  pr.xfr32BitInt(ret->d_serial);
  pr.xfr16BitInt(ret->d_flags);

  ret->d_bitmap.fromPacket(pr);
  return ret;
}

string CSYNCRecordContent::getZoneRepresentation(bool /* noDot */) const
{
  string ret;
  RecordTextWriter rtw(ret);
  rtw.xfr32BitInt(d_serial);
  rtw.xfr16BitInt(d_flags);

  return ret + d_bitmap.getZoneRepresentation();
}

////// end of CSYNC
