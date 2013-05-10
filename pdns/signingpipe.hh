#ifndef PDNS_SIGNINGPIPE
#define PDNS_SIGNINGPIPE
#include <vector>
#include <pthread.h>
#include <stdio.h>
#include "dnsseckeeper.hh"
#include "dns.hh"
using std::string;
using std::vector;

void writeLStringToSocket(int fd, const pdns::string& msg);
bool readLStringFromSocket(int fd, string& msg);

/** input: DNSResourceRecords ordered in qname,qtype (we emit a signature chunk on a break)
 *  output: "chunks" of those very same DNSResourceRecords, interleaved with signatures
 */

class ChunkedSigningPipe
{
public:
  typedef vector<DNSResourceRecord> rrset_t;
  typedef rrset_t chunk_t; // for now

  ChunkedSigningPipe(const std::string& signerName, bool mustSign, const pdns::string& servers=pdns::string(), unsigned int numWorkers=3);
  ~ChunkedSigningPipe();
  bool submit(const DNSResourceRecord& rr);
  chunk_t getChunk(bool final=false);
  int d_queued;
  AtomicCounter d_signed;
  int d_outstanding;
  unsigned int getReady();
private:
  void flushToSign();
  void dedupRRSet();
  void sendRRSetToWorker(); // dispatch RRSET to worker
  void addSignedToChunks(chunk_t* signedChunk);
  pair<vector<int>, vector<int> > waitForRW(bool rd, bool wr, int seconds);

  void worker(int n, int fd);

  static void* helperWorker(void* p);
  rrset_t* d_rrsetToSign;
  std::deque< std::vector<DNSResourceRecord> > d_chunks;
  string d_signer;

  chunk_t::size_type d_maxchunkrecords;

  std::vector<int> d_sockets;
  std::set<int> d_eof;
  unsigned int d_numworkers;
  vector<pthread_t> d_tids;
  bool d_mustSign;
  bool d_final;
  int d_submitted;
};

#endif
