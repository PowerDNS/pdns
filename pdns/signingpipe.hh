#ifndef PDNS_SIGNINGPIPE
#define PDNS_SIGNINGPIPE
#include <vector>
#include "dnsseckeeper.hh"
#include "dns.hh"
using std::string;
using std::vector;

/** input: DNSResourceRecords ordered in qname,qtype (we emit a signature chunk on a break)
 *  output: "chunks" of those very same DNSResourceRecords, interleaved with signatures
 */

class ChunkedSigningPipe
{
public:
  typedef vector<DNSResourceRecord> chunk_t; 
  
  ChunkedSigningPipe(DNSSECKeeper& dk, UeberBackend& db, const std::string& signerName) : d_dk(dk), d_db(db), d_signer(signerName), d_chunkrecords(100) {}
  bool submit(const DNSResourceRecord& rr);
  chunk_t getChunk(bool final=false);
private:
  void flushToSign();	

  chunk_t d_toSign, d_chunk;
  DNSSECKeeper& d_dk;
  UeberBackend& d_db;
  string d_signer;
  chunk_t::size_type d_chunkrecords;
};

#endif
