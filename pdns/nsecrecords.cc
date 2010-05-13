#include "dnsrecords.hh"

void NSECRecordContent::report(void)
{
  regist(1, 47, &make, &make, "NSEC");
}

DNSRecordContent* NSECRecordContent::make(const string& content)
{
  return new NSECRecordContent(content);
}

NSECRecordContent::NSECRecordContent(const string& content, const string& zone) : DNSRecordContent(47)
{
  RecordTextReader rtr(content, zone);
  rtr.xfrLabel(d_next);

  while(!rtr.eof()) {
    uint16_t type;
    rtr.xfrType(type);
    d_set.insert(type);
  }
}

void NSECRecordContent::toPacket(DNSPacketWriter& pw) 
{
  pw.xfrLabel(d_next);

  uint8_t res[34];
  memset(res, 0, sizeof(res));

  set<uint16_t>::const_iterator i;
  for(i=d_set.begin(); i != d_set.end() && *i<255; ++i){
    res[2+*i/8] |= 1 << (7-(*i%8));
  }
  int len=0;
  if(!d_set.empty()) 
    len=1+*--i/8;

  res[1]=len;

  string tmp;
  tmp.assign(res, res+len+2);
  pw.xfrBlob(tmp);
}

NSECRecordContent::DNSRecordContent* NSECRecordContent::make(const DNSRecord &dr, PacketReader& pr) 
{
  NSECRecordContent* ret=new NSECRecordContent();
  pr.xfrLabel(ret->d_next);
  string bitmap;
  pr.xfrBlob(bitmap);
  
  // 00 06 20 00 00 00 00 03  -> NS RRSIG NSEC  ( 2, 46, 47 ) counts from left
  
  if(bitmap.size() < 2)
    throw MOADNSException("NSEC record with impossibly small bitmap");
  
  if(bitmap[0])
    throw MOADNSException("Can't deal with NSEC mappings > 255 yet");
  
  unsigned int len=bitmap[1];
  if(bitmap.size()!=2+len)
    throw MOADNSException("Can't deal with multi-part NSEC mappings yet");
  
  for(unsigned int n=0 ; n < len ; ++n) {
    uint8_t val=bitmap[2+n];
    for(int bit = 0; bit < 8 ; ++bit , val>>=1)
      if(val & 1) {
	ret->d_set.insert((7-bit) + 8*(n));
      }
  }
  
  return ret;
}

string NSECRecordContent::getZoneRepresentation() const
{
  string ret;
  RecordTextWriter rtw(ret);
  rtw.xfrLabel(d_next);
  
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

NSEC3RecordContent::NSEC3RecordContent(const string& content, const string& zone) : DNSRecordContent(50)
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
  memset(res, 0, sizeof(res));

  set<uint16_t>::const_iterator i;
  for(i=d_set.begin(); i != d_set.end() && *i<255; ++i){
    res[2+*i/8] |= 1 << (7-(*i%8));
  }
  int len=0;
  if(!d_set.empty()) 
    len=1+*--i/8;

  res[1]=len;

  string tmp;
  tmp.assign(res, res+len+2);
  pw.xfrBlob(tmp);
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
  
  if(bitmap[0])
    throw MOADNSException("Can't deal with NSEC3 mappings > 255 yet");
  
  unsigned int bitmaplen=bitmap[1];
  if(bitmap.size()!=2+bitmaplen)
    throw MOADNSException("Can't deal with multi-part NSEC3 mappings yet");
  
  for(unsigned int n=0 ; n < bitmaplen ; ++n) {
    uint8_t val=bitmap[2+n];
    for(int bit = 0; bit < 8 ; ++bit , val>>=1)
      if(val & 1) {
        ret->d_set.insert((7-bit) + 8*(n));
      }
  }
  
  return ret;
}

string NSEC3RecordContent::getZoneRepresentation() const
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
}

DNSRecordContent* NSEC3PARAMRecordContent::make(const string& content)
{
  return new NSEC3PARAMRecordContent(content);
}

NSEC3PARAMRecordContent::NSEC3PARAMRecordContent(const string& content, const string& zone) : DNSRecordContent(51)
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
  cerr<<"salt: '"<<makeHexDump(d_salt)<<"', "<<d_salt.length()<<endl;
  pw.xfrBlob(d_salt);
}

NSEC3PARAMRecordContent::DNSRecordContent* NSEC3PARAMRecordContent::make(const DNSRecord &dr, PacketReader& pr) 
{
  NSEC3PARAMRecordContent* ret=new NSEC3PARAMRecordContent();
  pr.xfr8BitInt(ret->d_algorithm); 
	pr.xfr8BitInt(ret->d_flags); 
	pr.xfr16BitInt(ret->d_iterations); 
  pr.xfr8BitInt(ret->d_saltlength);
  pr.xfrHexBlob(ret->d_salt);
 
  return ret;
}

string NSEC3PARAMRecordContent::getZoneRepresentation() const
{
  string ret;
  RecordTextWriter rtw(ret);
  rtw.xfr8BitInt(d_algorithm); 
	rtw.xfr8BitInt(d_flags); 
	rtw.xfr16BitInt(d_iterations); 
  rtw.xfrHexBlob(d_salt);
  return ret;
}

