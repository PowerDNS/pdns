#ifndef PDNS_DNSWRITER_HH
#define PDNS_DNSWRITER_HH

#include <string>
#include <vector>
#include <map>
#include "dns.hh"
#include "dnsname.hh"
#include "namespaces.hh"
#include <arpa/inet.h>
/** this class can be used to write DNS packets. It knows about DNS in the sense that it makes
    the packet header and record headers.

    The model is:

    packetheader (recordheader recordcontent)*

    The packetheader needs to be updated with the amount of packets of each kind (answer, auth, additional)

    Each recordheader contains the length of a dns record.

    Calling convention:

    vector<uint8_t> content;
    DNSPacketWriter dpw(content, const string& qname, uint16_t qtype, uint16_t qclass=QClass:IN);  // sets the question
    dpw.startrecord("this.is.an.ip.address.", ns_t_a);    // does nothing, except store qname and qtype
    dpw.xfr32BitInt(0x01020304);                         // adds 4 bytes (0x01020304) to the record buffer
    dpw.startrecord("this.is.an.ip.address.", ns_t_a);    // aha! writes out dnsrecord header containing qname and qtype and length 4, plus the recordbuffer, which gets emptied
                                                         // new qname and qtype are stored
    dpw.xfr32BitInt(0x04030201);                         // adds 4 bytes (0x04030201) to the record buffer
    dpw.commit();                                        // writes out dnsrecord header containing qname and qtype and length 4, plus the recordbuffer

    // content now contains the ready packet, with 1 question and 2 answers

*/

class DNSPacketWriter : public boost::noncopyable
{

public:
  typedef vector<pair<DNSName, uint16_t> > lmap_t;

  //! Start a DNS Packet in the vector passed, with question qname, qtype and qclass
  DNSPacketWriter(vector<uint8_t>& content, const DNSName& qname, uint16_t  qtype, uint16_t qclass=QClass::IN, uint8_t opcode=0);

  /** Start a new DNS record within this packet for namq, qtype, ttl, class and in the requested place. Note that packets can only be written in natural order -
      ANSWER, AUTHORITY, ADDITIONAL */
  void startRecord(const DNSName& name, uint16_t qtype, uint32_t ttl=3600, uint16_t qclass=QClass::IN, DNSResourceRecord::Place place=DNSResourceRecord::ANSWER, bool compress=true);

  /** Shorthand way to add an Opt-record, for example for EDNS0 purposes */
  typedef vector<pair<uint16_t,std::string> > optvect_t;
  void addOpt(int udpsize, int extRCode, int Z, const optvect_t& options=optvect_t());

  /** needs to be called after the last record is added, but can be called again and again later on. Is called internally by startRecord too.
      The content of the vector<> passed to the constructor is inconsistent until commit is called.
   */
  void commit();

  uint32_t size(); // needs to be 32 bit because otherwise we don't see the wrap coming when it happened!

  /** Should the packet have grown too big for the writer's liking, rollback removes the record currently being written */
  void rollback();

  /** Discard all content except the question section */
  void truncate();

  void xfr48BitInt(uint64_t val);
  void xfr32BitInt(uint32_t val);
  void xfr16BitInt(uint16_t val);
  void xfrType(uint16_t val)
  {
    xfr16BitInt(val);
  }
  void xfrIP(const uint32_t& val)
  {
    xfr32BitInt(htonl(val));
  }
  void xfrIP6(const std::string& val)
  {
    xfrBlob(val,16);
  }
  void xfrTime(const uint32_t& val)
  {
    xfr32BitInt(val);
  }

  void xfr8BitInt(uint8_t val);

  void xfrName(const DNSName& label, bool compress=false, bool noDot=false);
  void xfrText(const string& text, bool multi=false);
  void xfrBlob(const string& blob, int len=-1);
  void xfrBlobNoSpaces(const string& blob, int len=-1);
  void xfrHexBlob(const string& blob, bool keepReading=false);

  uint16_t d_pos;

  dnsheader* getHeader();
  void getRecords(string& records);
  const vector<uint8_t>& getRecordBeingWritten() { return d_record; }

  void setCanonic(bool val)
  {
    d_canonic=val;
  }

  void setLowercase(bool val)
  {
    d_lowerCase=val;
  }
  vector <uint8_t>& getContent()
  {
    return d_content;
  }
  bool eof() { return true; } // we don't know how long the record should be

private:
  // We declare 1 uint_16 in the public section, these 3 align on a 8-byte boundry
  uint16_t d_stuff;
  uint16_t d_sor;
  uint16_t d_rollbackmarker; // start of last complete packet, for rollback

  vector <uint8_t>& d_content;
  vector <uint8_t> d_record;
  DNSName d_qname;
  DNSName d_recordqname;
  lmap_t d_labelmap;

  uint32_t d_recordttl;
  uint16_t d_recordqtype, d_recordqclass;

  uint16_t d_truncatemarker; // end of header, for truncate
  DNSResourceRecord::Place d_recordplace;
  bool d_canonic, d_lowerCase;
};

typedef vector<pair<string::size_type, string::size_type> > labelparts_t;
// bool labeltokUnescape(labelparts_t& parts, const DNSName& label);
std::vector<string> segmentDNSText(const string& text); // from dnslabeltext.rl
std::deque<string> segmentDNSName(const string& input ); // from dnslabeltext.rl
#endif
