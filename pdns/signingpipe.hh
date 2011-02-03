#ifndef PDNS_SIGNINGPIPE
#define PDNS_SIGNINGPIPE
#include <vector>
#include <pthread.h>
#include <stdio.h>
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
  typedef vector<DNSResourceRecord> rrset_t; 
  typedef rrset_t chunk_t; // for now
  
  ChunkedSigningPipe(DNSSECKeeper& dk, UeberBackend& db, const std::string& signerName, bool mustSign, unsigned int numWorkers=3);
  ~ChunkedSigningPipe();
  bool submit(const DNSResourceRecord& rr);
  chunk_t getChunk(bool final=false);
  int d_queued;
  AtomicCounter d_signed;
  int d_outstanding;
  unsigned int getReady();
private:
  void flushToSign();	
  
  void sendRRSetToWorker(); // dispatch RRSET to worker
  void worker(int n);
  
  static void* helperWorker(void* p);
  rrset_t* d_rrsetToSign;
  std::deque< std::vector<DNSResourceRecord> > d_chunks;
  DNSSECKeeper& d_dk;
  UeberBackend& d_db;
  string d_signer;
  
  chunk_t::size_type d_maxchunkrecords;
  
  std::vector<std::pair<int, int> > d_uppipes;
  int d_backpipe[2];
  
  unsigned int d_numworkers;
  vector<pthread_t> d_tids;
  bool d_mustSign;
};

#endif
