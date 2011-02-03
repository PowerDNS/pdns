#include "signingpipe.hh"
#include <boost/foreach.hpp>

struct StartHelperStruct
{
  StartHelperStruct(ChunkedSigningPipe* csp, int id) : d_csp(csp), d_id(id){}
  ChunkedSigningPipe* d_csp;
  int d_id;
};

void* ChunkedSigningPipe::helperWorker(void* p)
try
{
  StartHelperStruct shs=*(StartHelperStruct*)p;
  delete (StartHelperStruct*)p;
  
  shs.d_csp->worker(shs.d_id);
  return 0;
}
catch(std::exception& e) {
  cerr<<"Signing thread died with error "<<e.what()<<endl;
  return 0;
}

ChunkedSigningPipe::ChunkedSigningPipe(DNSSECKeeper& dk, UeberBackend& db, const std::string& signerName, bool mustSign, unsigned int workers) 
  : d_queued(0), d_outstanding(0), d_dk(dk), d_db(db),  d_signer(signerName), d_maxchunkrecords(100), d_numworkers(workers), d_tids(d_numworkers),
    d_mustSign(mustSign)
{
  d_rrsetToSign = new rrset_t;
  d_chunks.push_back(vector<DNSResourceRecord>());
  if(!d_mustSign)
    return;
  
  if(pipe(d_backpipe) < 0)
    throw runtime_error("Unable to create communication pipes in for ChunkedSigningPipe");
  
  Utility::setNonBlocking(d_backpipe[0]);
  int fds[2];
  
  for(unsigned int n=0; n < d_numworkers; ++n) {
    if(pipe(fds) < 0)
      throw runtime_error("Unable to create communication uppipes in for ChunkedSigningPipe");
    d_uppipes.push_back(make_pair(fds[0], fds[1]));
    
    pthread_create(&d_tids[n], 0, helperWorker, (void*) new StartHelperStruct(this, n));
  }
}

ChunkedSigningPipe::~ChunkedSigningPipe()
{
  delete d_rrsetToSign;
  if(!d_mustSign)
    return;
  for(vector<pair<int, int> >::const_iterator iter = d_uppipes.begin(); iter != d_uppipes.end(); ++iter)
    close(iter->second); // this will trigger all threads to exit
    
  void* res;
  for(unsigned int n = 0; n < d_numworkers; ++n)
    pthread_join(d_tids[n], &res);
  
  close(d_backpipe[1]);
  close(d_backpipe[0]);
  for(vector<pair<int, int> >::const_iterator iter = d_uppipes.begin(); iter != d_uppipes.end(); ++iter)
    close(iter->first); 
  cout<<"Did: "<<d_signed<<endl;
}

bool ChunkedSigningPipe::submit(const DNSResourceRecord& rr)
{
  if(!d_rrsetToSign->empty() && (d_rrsetToSign->begin()->qtype.getCode() != rr.qtype.getCode()  ||  !pdns_iequals(d_rrsetToSign->begin()->qname, rr.qname))) 
  {
    sendRRSetToWorker();
  }
  d_rrsetToSign->push_back(rr);
  return !d_chunks.empty() && d_chunks.back().size() > d_maxchunkrecords;
}

void ChunkedSigningPipe::sendRRSetToWorker() // it sounds so socialist!
{
  if(d_chunks.empty()) {
    cerr<<"Help!"<<endl;
  }
  if(!d_mustSign) {
    d_chunks.back().insert(d_chunks.back().end(), d_rrsetToSign->begin(), d_rrsetToSign->end());
    d_rrsetToSign->clear();
    return;
  }
  
  if(!d_rrsetToSign->empty()) {
    static int counter;
    d_rrsetToSign->reserve(2*d_rrsetToSign->size());
    if(write(d_uppipes[++counter % d_uppipes.size()].second, &d_rrsetToSign, sizeof(d_rrsetToSign)) != sizeof(d_rrsetToSign)) 
      throw runtime_error("Partial write or error communicating to signing thread");
    d_rrsetToSign = new rrset_t;
    d_outstanding++;
    d_queued++;
  }
  chunk_t* signedChunk;
  
  while(d_outstanding && read(d_backpipe[0], &signedChunk, sizeof(signedChunk)) > 0) {
    --d_outstanding;
    d_chunks.back().insert(d_chunks.back().end(), signedChunk->begin(), signedChunk->end());
    delete signedChunk;
    if(d_chunks.back().size() > d_maxchunkrecords) {
      d_chunks.push_back(vector<DNSResourceRecord>());
      break;
    }    
  }
}

unsigned int ChunkedSigningPipe::getReady()
{
   unsigned int sum=0; 
   BOOST_FOREACH(const std::vector<DNSResourceRecord>& v, d_chunks) {
     sum += v.size(); 
   }
   return sum;
}
void ChunkedSigningPipe::worker(int id)
{
  chunk_t* chunks[64];
  
  DNSSECKeeper dk;
  int res;
  for(;;) {
    res=read(d_uppipes[id].first, &chunks[0], 64*sizeof(chunk_t*));
    if(!res) {
      //cerr<<id<<" exiting"<<endl;
      break;
    }
    if(res % sizeof(chunk_t*))
      unixDie("error or partial read from ChunkedSigningPipe main thread");
    //cerr<<"Got "<<res/sizeof(chunk_t*)<<endl;
    for(unsigned int n = 0; n < res/sizeof(chunk_t*); ++n) {
      ++d_signed;
      addRRSigs(dk, d_db, d_signer, *chunks[n]); 
    }
      
    if(write(d_backpipe[1], &chunks[0], res) != res)
      unixDie("error writing back to ChunkedSigningPipe");
    
  }
}

void ChunkedSigningPipe::flushToSign()
{
  sendRRSetToWorker();
  d_rrsetToSign->clear();
}

vector<DNSResourceRecord> ChunkedSigningPipe::getChunk(bool final)
{
  if(final) {
    Utility::setBlocking(d_backpipe[0]);
    flushToSign();
  }
  
  vector<DNSResourceRecord> front=d_chunks.front();
  d_chunks.pop_front();
  if(d_chunks.empty())
    d_chunks.push_back(vector<DNSResourceRecord>());
  return front;
}
