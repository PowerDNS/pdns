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

void NSECRecordContent::report(void)
{
  regist(1, 47, &make, &make, "NSEC");
}

DNSRecordContent* NSECRecordContent::make(const string& content)
{
  return new NSECRecordContent(content);
}

NSECRecordContent::NSECRecordContent(const string& content, const string& zone) 
{
  RecordTextReader rtr(content, zone);
  rtr.xfrName(d_next);

  while(!rtr.eof()) {
    uint16_t type;
    rtr.xfrType(type);
    d_set.insert(type);
  }
}

void NSECRecordContent::toPacket(DNSPacketWriter& pw) 
{
  pw.xfrName(d_next);

  uint8_t res[34];
  set<uint16_t>::const_iterator i;
  int oldWindow = -1;
  int window = 0;
  int len = 0;
  string tmp;

  for(i=d_set.begin(); i != d_set.end(); ++i){
    uint16_t bit = (*i)%256;
    window = static_cast<int>((*i) / 256); 

    if (window != oldWindow) {
      if (oldWindow > -1) {
          res[0] = static_cast<unsigned char>(oldWindow);
          res[1] = static_cast<unsigned char>(len);
          tmp.assign(res, res+len+2);
          pw.xfrBlob(tmp);
      }
      memset(res, 0, 34);
      oldWindow = window;
    }
    res[2+bit/8] |= 1 << (7-(bit%8));
    len=1+bit/8;
  }

  res[0] = static_cast<unsigned char>(window);
  res[1] = static_cast<unsigned char>(len);
  tmp.assign(res, res+len+2);
  pw.xfrBlob(tmp);
}

NSECRecordContent::DNSRecordContent* NSECRecordContent::make(const DNSRecord &dr, PacketReader& pr) 
{
  NSECRecordContent* ret=new NSECRecordContent();
  pr.xfrName(ret->d_next);
  string bitmap;
  pr.xfrBlob(bitmap);
 
  // 00 06 20 00 00 00 00 03  -> NS RRSIG NSEC  ( 2, 46, 47 ) counts from left
  if(bitmap.empty())
    return ret;

  if(bitmap.size() < 2)
    throw MOADNSException("NSEC record with impossibly small bitmap");
  
  for(unsigned int n = 0; n+1 < bitmap.size();) {
    unsigned int window=static_cast<unsigned char>(bitmap[n++]);
    unsigned int blen=static_cast<unsigned char>(bitmap[n++]);

    // end if zero padding and ensure packet length
    if(window == 0 && blen == 0) break;
    if(n + blen > bitmap.size())
      throw MOADNSException("NSEC record with bitmap length > packet length");

    for(unsigned int k=0; k < blen; k++) {
      uint8_t val=bitmap[n++];
      for(int bit = 0; bit < 8 ; ++bit , val>>=1)
        if(val & 1) {
          ret->d_set.insert((7-bit) + 8*(k) + 256*window);
        }
      }
  }
  return ret;
}

string NSECRecordContent::getZoneRepresentation(bool noDot) const
{
  string ret;
  RecordTextWriter rtw(ret);
  rtw.xfrName(d_next);
  
  for(set<uint16_t>::const_iterator i=d_set.begin(); i!=d_set.end(); ++i) {
    ret+=" ";
    ret+=NumberToType(*i);
  }
  
  return ret;
}

////// begin of NSEC3

void NSEC3RecordContent::report(void)
{
  regist(1, 50, &make, &make, "NSEC3");
}

DNSRecordContent* NSEC3RecordContent::make(const string& content)
{
  return new NSEC3RecordContent(content);
}

NSEC3RecordContent::NSEC3RecordContent(const string& content, const string& zone)
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
    d_set.insert(type);
  }
}

void NSEC3RecordContent::toPacket(DNSPacketWriter& pw) 
{
  pw.xfr8BitInt(d_algorithm);
  pw.xfr8BitInt(d_flags);
  pw.xfr16BitInt(d_iterations);
  pw.xfr8BitInt(d_salt.length());
  pw.xfrBlob(d_salt);

  pw.xfr8BitInt(d_nexthash.length());
  pw.xfrBlob(d_nexthash);
  
  uint8_t res[34];
  set<uint16_t>::const_iterator i;
  int oldWindow = -1;
  int window = 0;
  int len = 0;
  string tmp;

  for(i=d_set.begin(); i != d_set.end(); ++i){
    uint16_t bit = (*i)%256;
    window = static_cast<int>((*i) / 256);

    if (window != oldWindow) {
      if (oldWindow > -1) {
          res[0] = static_cast<unsigned char>(oldWindow);
          res[1] = static_cast<unsigned char>(len);
          tmp.assign(res, res+len+2);
          pw.xfrBlob(tmp);
      }
      memset(res, 0, 34);
      oldWindow = window;
    }
    res[2+bit/8] |= 1 << (7-(bit%8));
    len=1+bit/8;
  }

  res[0] = static_cast<unsigned char>(window);
  res[1] = static_cast<unsigned char>(len);

  if (len) {
    tmp.assign(res, res+len+2);
    pw.xfrBlob(tmp);
  }
}

NSEC3RecordContent::DNSRecordContent* NSEC3RecordContent::make(const DNSRecord &dr, PacketReader& pr) 
{
  NSEC3RecordContent* ret=new NSEC3RecordContent();
  pr.xfr8BitInt(ret->d_algorithm);
  pr.xfr8BitInt(ret->d_flags);
  pr.xfr16BitInt(ret->d_iterations);
  uint8_t len;
  pr.xfr8BitInt(len);
  pr.xfrBlob(ret->d_salt, len);

  pr.xfr8BitInt(len);
  pr.xfrBlob(ret->d_nexthash, len);
  
  string bitmap;
  pr.xfrBlob(bitmap);
  
  // 00 06 20 00 00 00 00 03  -> NS RRSIG NSEC  ( 2, 46, 47 ) counts from left
  
  if(bitmap.empty())
    return ret;

  if(bitmap.size() < 2)
    throw MOADNSException("NSEC3 record with impossibly small bitmap");

  for(unsigned int n = 0; n+1 < bitmap.size();) {
    unsigned int window=static_cast<unsigned char>(bitmap[n++]);
    unsigned int innerlen=static_cast<unsigned char>(bitmap[n++]);
    
    // end if zero padding and ensure packet length
    if(window == 0&&innerlen == 0) break;
    if(n+innerlen>bitmap.size())
      throw MOADNSException("NSEC record with bitmap length > packet length");

    for(unsigned int k=0; k < innerlen; k++) {
      uint8_t val=bitmap[n++];
      for(int bit = 0; bit < 8 ; ++bit , val>>=1)
        if(val & 1) {
          ret->d_set.insert((7-bit) + 8*(k) + 256*window);
        }
      }
  }
  return ret;
}

string NSEC3RecordContent::getZoneRepresentation(bool noDot) const
{
  string ret;
  RecordTextWriter rtw(ret);
  rtw.xfr8BitInt(d_algorithm);
  rtw.xfr8BitInt(d_flags);
  rtw.xfr16BitInt(d_iterations);

  rtw.xfrHexBlob(d_salt);
  rtw.xfrBase32HexBlob(d_nexthash);
  for(set<uint16_t>::const_iterator i=d_set.begin(); i!=d_set.end(); ++i) {
    ret+=" ";
    ret+=NumberToType(*i);
  }
  
  return ret;
}


void NSEC3PARAMRecordContent::report(void)
{
  regist(1, 51, &make, &make, "NSEC3PARAM");
  regist(254, 51, &make, &make, "NSEC3PARAM");
}

DNSRecordContent* NSEC3PARAMRecordContent::make(const string& content)
{
  return new NSEC3PARAMRecordContent(content);
}

NSEC3PARAMRecordContent::NSEC3PARAMRecordContent(const string& content, const string& zone) 
{
  RecordTextReader rtr(content, zone);
  rtr.xfr8BitInt(d_algorithm); 
  rtr.xfr8BitInt(d_flags); 
  rtr.xfr16BitInt(d_iterations); 
  rtr.xfrHexBlob(d_salt);
}

void NSEC3PARAMRecordContent::toPacket(DNSPacketWriter& pw) 
{
  pw.xfr8BitInt(d_algorithm); 
        pw.xfr8BitInt(d_flags); 
        pw.xfr16BitInt(d_iterations); 
  pw.xfr8BitInt(d_salt.length());
  // cerr<<"salt: '"<<makeHexDump(d_salt)<<"', "<<d_salt.length()<<endl;
  pw.xfrBlob(d_salt);
}

NSEC3PARAMRecordContent::DNSRecordContent* NSEC3PARAMRecordContent::make(const DNSRecord &dr, PacketReader& pr) 
{
  NSEC3PARAMRecordContent* ret=new NSEC3PARAMRecordContent();
  pr.xfr8BitInt(ret->d_algorithm); 
        pr.xfr8BitInt(ret->d_flags); 
        pr.xfr16BitInt(ret->d_iterations); 
  uint8_t len;
  pr.xfr8BitInt(len);
  pr.xfrHexBlob(ret->d_salt, len);
  return ret;
}

string NSEC3PARAMRecordContent::getZoneRepresentation(bool noDot) const
{
  string ret;
  RecordTextWriter rtw(ret);
  rtw.xfr8BitInt(d_algorithm); 
        rtw.xfr8BitInt(d_flags); 
        rtw.xfr16BitInt(d_iterations); 
  rtw.xfrHexBlob(d_salt);
  return ret;
}

