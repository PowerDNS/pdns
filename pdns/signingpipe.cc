#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "signingpipe.hh"
#include "misc.hh"
#include <poll.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>

// deal with partial reads
namespace {
int readn(int fd, void* buffer, unsigned int len)
{
  unsigned int pos=0;
  int res;
  for(;;) {
    res = read(fd, (char*)buffer + pos, len - pos);
    if(res == 0) {
      if(pos)
        throw runtime_error("Signing Pipe remote shut down in the middle of a message");
      else {
        //cerr<<"Got decent EOF on "<<fd<<endl;
        return 0;
      }
    }
      
    if(res < 0) {
      if(errno == EAGAIN || errno == EINTR) {
        if(pos==0)
          return -1;
        waitForData(fd, -1); 
        continue;
      }
      unixDie("Reading from socket in Signing Pipe loop");
    }
  
    pos+=res;
    if(pos == len)
      break;
  }
  return len;
}
}

void* ChunkedSigningPipe::helperWorker(ChunkedSigningPipe* csp, int fd)
try {
  csp->worker(fd);
  return nullptr;
}
catch(...) {
  g_log<<Logger::Error<<"Unknown exception in signing thread occurred"<<endl;
  return nullptr;
}

ChunkedSigningPipe::ChunkedSigningPipe(const DNSName& signerName, bool mustSign, unsigned int workers)
  : d_signed(0), d_queued(0), d_outstanding(0), d_numworkers(workers), d_submitted(0), d_signer(signerName),
    d_maxchunkrecords(100), d_threads(d_numworkers), d_mustSign(mustSign), d_final(false)
{
  d_rrsetToSign = make_unique<rrset_t>();
  d_chunks.push_back(vector<DNSZoneRecord>()); // load an empty chunk
  
  if(!d_mustSign)
    return;
  
  int fds[2];
  
  for(unsigned int n=0; n < d_numworkers; ++n) {
    if(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) 
      throw runtime_error("Unable to create communication socket in for ChunkedSigningPipe");
    setCloseOnExec(fds[0]);
    setCloseOnExec(fds[1]);
    d_threads[n] = std::thread(helperWorker, this, fds[1]);
    setNonBlocking(fds[0]);
    d_sockets.push_back(fds[0]);
    d_outstandings[fds[0]] = 0;
  }
}

ChunkedSigningPipe::~ChunkedSigningPipe()
{
  if(!d_mustSign)
    return;

  for(int fd :  d_sockets) {
    close(fd); // this will trigger all threads to exit
  }

  for(auto& thread : d_threads) {
    thread.join();
  }
  //cout<<"Did: "<<d_signed<<", records (!= chunks) submitted: "<<d_submitted<<endl;
}

namespace {
bool
dedupLessThan(const DNSZoneRecord& a, const DNSZoneRecord &b)
{
  return make_tuple(a.dr.d_content->getZoneRepresentation(), a.dr.d_ttl) < make_tuple(b.dr.d_content->getZoneRepresentation(), b.dr.d_ttl);  // XXX SLOW SLOW SLOW
}

bool dedupEqual(const DNSZoneRecord& a, const DNSZoneRecord &b)
{
  return make_tuple(a.dr.d_content->getZoneRepresentation(), a.dr.d_ttl) == make_tuple(b.dr.d_content->getZoneRepresentation(), b.dr.d_ttl);  // XXX SLOW SLOW SLOW
}
}

void ChunkedSigningPipe::dedupRRSet()
{
  // our set contains contains records for one type and one name, but might not be sorted otherwise
  sort(d_rrsetToSign->begin(), d_rrsetToSign->end(), dedupLessThan);
  d_rrsetToSign->erase(unique(d_rrsetToSign->begin(), d_rrsetToSign->end(), dedupEqual), d_rrsetToSign->end());
}

bool ChunkedSigningPipe::submit(const DNSZoneRecord& rr)
{
  ++d_submitted;
  // check if we have a full RRSET to sign
  if(!d_rrsetToSign->empty() && (d_rrsetToSign->begin()->dr.d_type != rr.dr.d_type ||  d_rrsetToSign->begin()->dr.d_name != rr.dr.d_name)) 
  {
    dedupRRSet();
    sendRRSetToWorker();
  }
  d_rrsetToSign->push_back(rr);
  return !d_chunks.empty() && d_chunks.front().size() >= d_maxchunkrecords; // "you can send more"
}

pair<vector<int>, vector<int> > ChunkedSigningPipe::waitForRW(bool rd, bool wr, int seconds)
{
  vector<pollfd> pfds;

  for(unsigned int n = 0; n < d_sockets.size(); ++n) {    
    if(d_eof.count(d_sockets[n]))  
      continue;
    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = d_sockets[n];
    if(rd)
      pfd.events |= POLLIN;
    if(wr)
      pfd.events |= POLLOUT;
    pfds.push_back(pfd);
  }

  int res = poll(&pfds[0], pfds.size(), (seconds < 0) ? -1 : (seconds * 1000)); // -1 = infinite
  if(res < 0)
    unixDie("polling for activity from signers, "+std::to_string(d_sockets.size()));
  pair<vector<int>, vector<int> > vects;
  for(unsigned int n = 0; n < pfds.size(); ++n) 
    if(pfds[n].revents & POLLIN)
      vects.first.push_back(pfds[n].fd);
    else if(pfds[n].revents & POLLOUT)
      vects.second.push_back(pfds[n].fd);
  
  return vects;
}

void ChunkedSigningPipe::addSignedToChunks(std::unique_ptr<chunk_t>& signedChunk)
{
  chunk_t::const_iterator from = signedChunk->begin();
  
  while(from != signedChunk->end()) {
    chunk_t& fillChunk = d_chunks.back();
    chunk_t::size_type room = d_maxchunkrecords - fillChunk.size();
    
    unsigned int fit = std::min(room, (chunk_t::size_type)(signedChunk->end() - from));
  
    d_chunks.back().insert(fillChunk.end(), from , from + fit);
    from+=fit;

    if(from != signedChunk->end()) // it didn't fit, so add a new chunk
      d_chunks.push_back(chunk_t());
  }
}

void ChunkedSigningPipe::sendRRSetToWorker() // it sounds so socialist!
{
  if(!d_mustSign) {
    addSignedToChunks(d_rrsetToSign);
    d_rrsetToSign->clear();
    return;
  }
  
  if(d_final && !d_outstanding) // nothing to do!
    return;
  
  bool wantRead, wantWrite;
  
  wantWrite = !d_rrsetToSign->empty();
  wantRead = d_outstanding || wantWrite;  // if we wrote, we want to read
  
  pair<vector<int>, vector<int> > rwVect;
  
  rwVect = waitForRW(wantRead, wantWrite, -1); // wait for something to happen
  
  if(wantWrite && !rwVect.second.empty()) {
    random_shuffle(rwVect.second.begin(), rwVect.second.end()); // pick random available worker
    auto ptr = d_rrsetToSign.release();
    writen2(*rwVect.second.begin(), &ptr, sizeof(ptr));
    d_rrsetToSign = make_unique<rrset_t>();
    d_outstandings[*rwVect.second.begin()]++;
    d_outstanding++;
    d_queued++;
    wantWrite=false;
  } 
  
  if(wantRead) {
    while(d_outstanding) {
      for(int fd :  rwVect.first) {
        if(d_eof.count(fd))
          continue;
        
        while(d_outstanding) {
          chunk_t* chunk = nullptr;
          int res = readn(fd, &chunk, sizeof(chunk));
          if(!res) {
            if (d_outstandings[fd] > 0) {
              throw std::runtime_error("A signing pipe worker died while we were waiting for its result");
            }
            d_eof.insert(fd);
            break;
          }
          if(res < 0) {
            if(errno != EAGAIN && errno != EINTR)
              unixDie("Error reading signed chunk from thread");
            else
              break;
          }

          std::unique_ptr<rrset_t> chunkPtr(chunk);
          chunk = nullptr;
          --d_outstanding;
          d_outstandings[fd]--;
          
          addSignedToChunks(chunkPtr);
        }
      }
      if(!d_outstanding || !d_final)
        break;
      rwVect = waitForRW(true, false, -1); // wait for something to happen
    }
  }
  
  if(wantWrite) {  // our optimization above failed, we now wait synchronously
    rwVect = waitForRW(false, wantWrite, -1); // wait for something to happen
    random_shuffle(rwVect.second.begin(), rwVect.second.end()); // pick random available worker
    auto ptr = d_rrsetToSign.release();
    writen2(*rwVect.second.begin(), &ptr, sizeof(ptr));
    d_rrsetToSign = make_unique<rrset_t>();
    d_outstandings[*rwVect.second.begin()]++;
    d_outstanding++;
    d_queued++;
  }
  
}

unsigned int ChunkedSigningPipe::getReady() const
{
   unsigned int sum=0; 
   for(const auto& v :  d_chunks) {
     sum += v.size(); 
   }
   return sum;
}

void ChunkedSigningPipe::worker(int fd)
try
{
  UeberBackend db("key-only");
  DNSSECKeeper dk(&db);
  
  chunk_t* chunk = nullptr;
  int res;
  for(;;) {
    res = readn(fd, &chunk, sizeof(chunk));
    if(!res)
      break;
    if(res < 0)
      unixDie("reading object pointer to sign from pdns");
    try {
      set<DNSName> authSet;
      authSet.insert(d_signer);
      addRRSigs(dk, db, authSet, *chunk);
      ++d_signed;

      writen2(fd, &chunk, sizeof(chunk));
      chunk = nullptr;
    }
    catch(const PDNSException& pe) {
      delete chunk;
      throw;
    }
    catch(const std::exception& e) {
      delete chunk;
      throw;
    }
  }
  close(fd);
}
catch(const PDNSException& pe)
{
  g_log<<Logger::Error<<"Signing thread died because of PDNSException: "<<pe.reason<<endl;
  close(fd);
}
catch(const std::exception& e)
{
  g_log<<Logger::Error<<"Signing thread died because of std::exception: "<<e.what()<<endl;
  close(fd);
}

void ChunkedSigningPipe::flushToSign()
{
  sendRRSetToWorker();
  d_rrsetToSign->clear();
}

vector<DNSZoneRecord> ChunkedSigningPipe::getChunk(bool final)
{
  if(final && !d_final) {
    // this means we should keep on reading until d_outstanding == 0
    d_final = true;
    flushToSign();
    
    for(int fd :  d_sockets) {
      shutdown(fd, SHUT_WR); // perhaps this transmits EOF the other side
      //cerr<<"shutdown of "<<fd<<endl;
    }
  }
  if(d_final)
    flushToSign(); // should help us wait
  vector<DNSZoneRecord> front=d_chunks.front();
  d_chunks.pop_front();
  if(d_chunks.empty())
    d_chunks.push_back(vector<DNSZoneRecord>());
/*  if(d_final && front.empty())
      cerr<<"getChunk returning empty in final"<<endl; */
  return front;
}


