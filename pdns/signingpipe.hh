#ifndef PDNS_SIGNINGPIPE
#define PDNS_SIGNINGPIPE
#include <vector>
#include <pthread.h>
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
  
  ChunkedSigningPipe(DNSSECKeeper& dk, UeberBackend& db, const std::string& signerName, bool mustSign, unsigned int numWorkers=3);
  ~ChunkedSigningPipe();
  bool submit(const DNSResourceRecord& rr);
  chunk_t getChunk(bool final=false);
private:
  void flushToSign();	
  
  void sendChunkToSign(); // dispatch chunk to worker
  void worker();
  
  static void* helperWorker(void* p);
  chunk_t d_toSign, d_chunk;
  DNSSECKeeper& d_dk;
  UeberBackend& d_db;
  string d_signer;
  chunk_t::size_type d_chunkrecords;
  
  int d_uppipe[2], d_backpipe[2];
  int d_outstanding;
  unsigned int d_numworkers;
  vector<pthread_t> d_tids;
  static AtomicCounter s_workerid;
  bool d_mustSign;
};

#endif
