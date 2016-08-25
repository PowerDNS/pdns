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
#ifndef PDNS_SIGNINGPIPE
#define PDNS_SIGNINGPIPE
#include <vector>
#include <pthread.h>
#include <stdio.h>
#include "dnsseckeeper.hh"
#include "dns.hh"

void writeLStringToSocket(int fd, const string& msg);
bool readLStringFromSocket(int fd, string& msg);

/** input: DNSResourceRecords ordered in qname,qtype (we emit a signature chunk on a break)
 *  output: "chunks" of those very same DNSResourceRecords, interleaved with signatures
 */

class ChunkedSigningPipe
{
public:
  typedef vector<DNSResourceRecord> rrset_t; 
  typedef rrset_t chunk_t; // for now
  
  ChunkedSigningPipe(const DNSName& signerName, bool mustSign, /* FIXME servers is unused? */ const string& servers=string(), unsigned int numWorkers=3);
  ~ChunkedSigningPipe();
  bool submit(const DNSResourceRecord& rr);
  chunk_t getChunk(bool final=false);

  std::atomic<unsigned long> d_signed;
  int d_queued;
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

  unsigned int d_numworkers;
  int d_submitted;

  rrset_t* d_rrsetToSign;
  std::deque< std::vector<DNSResourceRecord> > d_chunks;
  DNSName d_signer;
  
  chunk_t::size_type d_maxchunkrecords;
  
  std::vector<int> d_sockets;
  std::set<int> d_eof;
  vector<pthread_t> d_tids;
  bool d_mustSign;
  bool d_final;
};

#endif
