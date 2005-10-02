#ifndef PDNS_DNSWRITER_HH
#define PDNS_DNSWRITER_HH

#include <string>
#include <vector>
#include <stdint.h>

using namespace std;

/** this class can be used to write DNS packets. It knows about DNS in the sense that it makes 
    the packet header and record headers.

    The model is:

    packetheader (recordheader recordcontent)*

    The packetheader needs to be updated with the amount of packets of each kind (answer, auth, additional)
    
    Each recordheader contains the length of a dns record.

    Calling convention:

    vector<uint8_t> content;
    DNSPacketWriter dpw(content, const string& qname, uint16_t qtype, uint16_t qclass=1);  // sets the question
    dpw.startrecord("this.is.an.ip.address", ns_t_a);    // does nothing, except store qname and qtype
    dpw.xfr32BitInt(0x01020304);                         // adds 4 bytes (0x01020304) to the record buffer
    dpw.startrecord("this.is.an.ip.address", ns_t_a);    // aha! writes out dnsrecord header containing qname and qtype and length 4, plus the recordbuffer, which gets emptied
                                                         // new qname and qtype are stored
    dpw.xfr32BitInt(0x04030201);                         // adds 4 bytes (0x04030201) to the record buffer
    dpw.commit();                                        // writes out dnsrecord header containing qname and qtype and length 4, plus the recordbuffer

    // content now contains the ready packet, with 1 question and 2 answers

*/

class DNSPacketWriter
{
public:
  enum Place {ANSWER=1, AUTHORITY=2, ADDITIONAL=3}; 

  DNSPacketWriter(vector<uint8_t>& content, const string& qname, uint16_t  qtype, uint16_t qclass=1);
  void startRecord(const string& name, uint16_t qtype, uint32_t ttl=3600, uint16_t qclass=1, Place place=ANSWER);
  void addOpt(int udpsize, int extRCode, int Z);

  void xfr32BitInt(uint32_t val);
  void xfr16BitInt(uint16_t val);
  void xfrType(uint16_t val)
  {
    xfr16BitInt(val);
  }
  void xfrIP(const uint32_t& val)
  {
    xfr32BitInt(val);
  }
  void xfrTime(const uint32_t& val)
  {
    xfr32BitInt(val);
  }


  void xfr8BitInt(uint8_t val);

  void xfrLabel(const string& label);
  void xfrText(const string& text);
  void xfrBlob(const string& blob);
  void commit();
  
  uint16_t d_pos;

  void setRD(bool rd=true);
private:
  vector<uint8_t>& d_content;
  vector <uint8_t> d_record;
  string d_qname;
  uint16_t d_qtype, d_qclass;
  string d_recordqname;
  uint16_t d_recordqtype, d_recordqclass;
  uint32_t d_recordttl;
};
#endif
