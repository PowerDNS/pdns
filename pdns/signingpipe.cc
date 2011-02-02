#include "signingpipe.hh"

AtomicCounter ChunkedSigningPipe::s_workerid;

void* ChunkedSigningPipe::helperWorker(void* p)
try
{
  ChunkedSigningPipe* us = (ChunkedSigningPipe*)p;
  us->worker();
  return 0;
}
catch(std::exception& e) {
  cerr<<"Signing thread died with error "<<e.what()<<endl;
}

ChunkedSigningPipe::ChunkedSigningPipe(DNSSECKeeper& dk, UeberBackend& db, const std::string& signerName, bool mustSign, unsigned int workers) 
  : d_dk(dk), d_db(db), d_signer(signerName), d_chunkrecords(100), d_outstanding(0), d_numworkers(workers), d_tids(d_numworkers),
    d_mustSign(mustSign)
{
  if(!d_mustSign)
    return;
  if(pipe(d_uppipe) < 0 || pipe(d_backpipe))
    throw runtime_error("Unable to create communication pipes in for ChunkedSigningPipe");
  
  Utility::setNonBlocking(d_backpipe[0]);
  for(unsigned int n=0; n < d_numworkers; ++n) {
    pthread_create(&d_tids[n], 0, helperWorker, (void*) this);
  }
}

ChunkedSigningPipe::~ChunkedSigningPipe()
{
  if(!d_mustSign)
    return;
  close(d_uppipe[1]); // this will trigger all threads to exit
  void* res;
  for(unsigned int n = 0; n < d_numworkers; ++n)
    pthread_join(d_tids[n], &res);
  
  close(d_backpipe[1]);
  close(d_backpipe[0]);
  close(d_uppipe[0]);
}

bool ChunkedSigningPipe::submit(const DNSResourceRecord& rr)
{
  if(!d_toSign.empty() && (d_toSign.begin()->qtype.getCode() != rr.qtype.getCode()  ||  !pdns_iequals(d_toSign.begin()->qname, rr.qname))) 
  {
    flushToSign();
  }
  d_toSign.push_back(rr);
  return d_chunk.size() > d_chunkrecords;
}

void ChunkedSigningPipe::sendChunkToSign()
{
  if(!d_mustSign) {
    d_chunk.insert(d_chunk.end(), d_toSign.begin(), d_toSign.end());
    d_toSign.clear();
    return;
  }
  if(!d_toSign.empty()) {
    chunk_t* toSign = new chunk_t(d_toSign);
    
    if(write(d_uppipe[1], &toSign, sizeof(toSign)) != sizeof(toSign)) 
      throw runtime_error("Partial write or error communicating to signing thread");
    d_outstanding++;
  }
  chunk_t* signedChunk;
  
  while(d_outstanding && read(d_backpipe[0], &signedChunk, sizeof(signedChunk)) > 0) {
    --d_outstanding;
    d_chunk.insert(d_chunk.end(), signedChunk->begin(), signedChunk->end());
    delete signedChunk;
  }
  
  d_toSign.clear();
}

void ChunkedSigningPipe::worker()
{
  //int my_id = ++s_workerid;
  // cout<<my_id<<" worker reporting!"<<endl;
  chunk_t* chunk;
  
  DNSSECKeeper dk;
  int res;
  for(;;) {
    res=read(d_uppipe[0], &chunk, sizeof(chunk));
    if(!res) {
      // cerr<<my_id<<" exiting"<<endl;
      break;
    }
    if(res != sizeof(chunk))
      unixDie("error or partial read from ChunkedSigningPipe main thread");
    // cout<< my_id <<" worker signing!"<<endl;
    addRRSigs(dk, d_db, d_signer, *chunk); // should start returning sigs separately instead of interleaved  
    if(write(d_backpipe[1], &chunk, sizeof(chunk)) != sizeof(chunk))
      unixDie("error writing back to ChunkedSigningPipe");
  }
}

void ChunkedSigningPipe::flushToSign()
{
  sendChunkToSign();
  d_toSign.clear();
}

vector<DNSResourceRecord> ChunkedSigningPipe::getChunk(bool final)
{
  if(final) {
    Utility::setBlocking(d_backpipe[0]);
    flushToSign();
  }
  
  chunk_t::size_type amount=min(d_chunkrecords, d_chunk.size());
  chunk_t chunk(d_chunk.begin(), d_chunk.begin() + amount);
  
  d_chunk.erase(d_chunk.begin(), d_chunk.begin() + amount);
  
  return chunk;
}
