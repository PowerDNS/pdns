#include "signingpipe.hh"
#include "misc.hh"
#include <poll.h>
#include <boost/foreach.hpp>
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


// used to pass information to the new thread
struct StartHelperStruct
{
  StartHelperStruct(ChunkedSigningPipe* csp, int id, int fd) : d_csp(csp), d_id(id), d_fd(fd){}
  ChunkedSigningPipe* d_csp;
  int d_id;
  int d_fd;
};

// used to launcht the new thread
void* ChunkedSigningPipe::helperWorker(void* p)
try
{
  StartHelperStruct shs=*(StartHelperStruct*)p;
  delete (StartHelperStruct*)p;
  
  shs.d_csp->worker(shs.d_id, shs.d_fd);
  return 0;
}
catch(std::exception& e) {
  L<<Logger::Error<<"Signing thread died with error "<<e.what()<<endl;
  return 0;
}

ChunkedSigningPipe::ChunkedSigningPipe(const std::string& signerName, bool mustSign, const pdns::string& servers, unsigned int workers) 
  : d_queued(0), d_outstanding(0), d_signer(signerName), d_maxchunkrecords(100), d_numworkers(workers), d_tids(d_numworkers),
    d_mustSign(mustSign), d_final(false), d_submitted(0)
{
  d_rrsetToSign = new rrset_t;
  d_chunks.push_back(vector<DNSResourceRecord>()); // load an empty chunk
  
  if(!d_mustSign)
    return;
  
  int fds[2];
  
  for(unsigned int n=0; n < d_numworkers; ++n) {
    if(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) 
      throw runtime_error("Unable to create communication socket in for ChunkedSigningPipe");
    Utility::setCloseOnExec(fds[0]);
    Utility::setCloseOnExec(fds[1]);
    pthread_create(&d_tids[n], 0, helperWorker, (void*) new StartHelperStruct(this, n, fds[1]));
    Utility::setNonBlocking(fds[0]);
    d_sockets.push_back(fds[0]);
  }
}

ChunkedSigningPipe::~ChunkedSigningPipe()
{
  delete d_rrsetToSign;
  if(!d_mustSign)
    return;
  BOOST_FOREACH(int fd, d_sockets) {
    close(fd); // this will trigger all threads to exit
  }
    
  void* res;
  BOOST_FOREACH(pthread_t& tid, d_tids) {
    pthread_join(tid, &res);
  }
  //cout<<"Did: "<<d_signed<<", records (!= chunks) submitted: "<<d_submitted<<endl;
}

namespace {
bool dedupLessThan(const DNSResourceRecord& a, const DNSResourceRecord &b)
{
  if(tie(a.content, a.ttl) < tie(b.content, b.ttl))
    return true;
  if(a.qtype.getCode() == QType::MX || a.qtype.getCode() == QType::SRV)
    return a.priority < b.priority;
  return false;
}

bool dedupEqual(const DNSResourceRecord& a, const DNSResourceRecord &b)
{
  if(tie(a.content, a.ttl) != tie(b.content, b.ttl))
    return false;
  if(a.qtype.getCode() == QType::MX || a.qtype.getCode() == QType::SRV)
    return a.priority == b.priority;
  return true;
}
}

void ChunkedSigningPipe::dedupRRSet()
{
  // our set contains contains records for one type and one name, but might not be sorted otherwise
  sort(d_rrsetToSign->begin(), d_rrsetToSign->end(), dedupLessThan);
  d_rrsetToSign->erase(unique(d_rrsetToSign->begin(), d_rrsetToSign->end(), dedupEqual), d_rrsetToSign->end());
}

bool ChunkedSigningPipe::submit(const DNSResourceRecord& rr)
{
  ++d_submitted;
  // check if we have a full RRSET to sign
  if(!d_rrsetToSign->empty() && (d_rrsetToSign->begin()->qtype.getCode() != rr.qtype.getCode()  ||  !pdns_iequals(d_rrsetToSign->begin()->qname, rr.qname))) 
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
    unixDie("polling for activity from signers, "+lexical_cast<string>(d_sockets.size()));
  pair<vector<int>, vector<int> > vects;
  for(unsigned int n = 0; n < pfds.size(); ++n) 
    if(pfds[n].revents & POLLIN)
      vects.first.push_back(pfds[n].fd);
    else if(pfds[n].revents & POLLOUT)
      vects.second.push_back(pfds[n].fd);
  
  return vects;
}

void ChunkedSigningPipe::addSignedToChunks(chunk_t* signedChunk)
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
    writen2(*rwVect.second.begin(), &d_rrsetToSign, sizeof(d_rrsetToSign));
    d_rrsetToSign = new rrset_t;
    d_outstanding++;
    d_queued++;
    wantWrite=false;
  } 
  
  if(wantRead) {
    while(d_outstanding) {
      chunk_t* chunk;
      
      BOOST_FOREACH(int fd, rwVect.first) {
        if(d_eof.count(fd))
          continue;
        
        while(d_outstanding) {
          int res = readn(fd, &chunk, sizeof(chunk));
          if(!res) {
            d_eof.insert(fd);
            break;
          }
          if(res < 0) {
            if(errno != EAGAIN && errno != EINTR)
              unixDie("Error reading signed chunk from thread");
            else
              break;
          }
          
          --d_outstanding;
          
          addSignedToChunks(chunk);
          
          delete chunk;
        }
      }
      if(!d_outstanding || !d_final)
        break;
      rwVect = waitForRW(1, 0, -1); // wait for something to happen  
    }
  }
  
  if(wantWrite) {  // our optimization above failed, we now wait synchronously
    rwVect = waitForRW(0, wantWrite, -1); // wait for something to happen  
    random_shuffle(rwVect.second.begin(), rwVect.second.end()); // pick random available worker
    writen2(*rwVect.second.begin(), &d_rrsetToSign, sizeof(d_rrsetToSign));
    d_rrsetToSign = new rrset_t;
    d_outstanding++;
    d_queued++;
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
void ChunkedSigningPipe::worker(int id, int fd)
try
{
  DNSSECKeeper dk;
  UeberBackend db("key-only");
  
  chunk_t* chunk;
  int res;
  for(;;) {
    res = readn(fd, &chunk, sizeof(chunk));
    if(!res)
      break;
    if(res < 0)
      unixDie("reading object pointer to sign from pdns");
    set<string, CIStringCompare> authSet;
    authSet.insert(d_signer);
    addRRSigs(dk, db, authSet, *chunk);
    ++d_signed;
    
    writen2(fd, &chunk, sizeof(chunk));
  }
  close(fd);
}
catch(std::exception& e)
{
  L<<Logger::Error<<"Signing thread died because of std::exception: "<<e.what()<<endl;
  close(fd);
}

void ChunkedSigningPipe::flushToSign()
{
  sendRRSetToWorker();
  d_rrsetToSign->clear();
}

vector<DNSResourceRecord> ChunkedSigningPipe::getChunk(bool final)
{
  if(final && !d_final) {
    // this means we should keep on reading until d_outstanding == 0
    d_final = true;
    flushToSign();
    
    BOOST_FOREACH(int fd, d_sockets) {
      shutdown(fd, SHUT_WR); // perhaps this transmits EOF the other side
      //cerr<<"shutdown of "<<fd<<endl;
    }
  }
  if(d_final)
    flushToSign(); // should help us wait
  vector<DNSResourceRecord> front=d_chunks.front();
  d_chunks.pop_front();
  if(d_chunks.empty())
    d_chunks.push_back(vector<DNSResourceRecord>());
  if(d_final && front.empty())
    ; // cerr<<"getChunk returning empty in final"<<endl;
  return front;
}

#if 0

  ServiceTuple st;
  ComboAddress remote;
  if(!servers.empty()) {
    st.port=2000;
    parseService(servers, st);
    remote=ComboAddress(st.host, st.port);
  }
  
  ///
    if(!servers.empty()) {
      fds[0] = socket(AF_INET, SOCK_STREAM, 0);
      fds[1] = -1;
      
      if(connect(fds[0], (struct sockaddr*)&remote, remote.getSocklen()) < 0)
        unixDie("Connecting to signing server");
    }
    else {
/////
      signal(SIGCHLD, SIG_IGN);
      if(!fork()) { // child
        dup2(fds[1], 0);
        execl("./pdnssec", "./pdnssec", "--config-dir=./", "signing-slave", NULL);
        // helperWorker(new StartHelperStruct(this, n));
        return;
      }
      else 
        close(fds[1]);
#endif

#if 0
bool readLStringFromSocket(int fd, string& msg)
{
  msg.clear();
  uint32_t len;
  if(!readn(fd, &len, sizeof(len)))
    return false;
  
  len = ntohl(len);
  
  scoped_array<char> buf(new char[len]);
  readn(fd, buf.get(), len);
  
  msg.assign(buf.get(), len);
  return true;
}
void writeLStringToSocket(int fd, const string& msg)
{
  string realmsg;
  uint32_t len = htonl(msg.length());
  string tot((char*)&len, 4);
  tot+=msg;
  
  writen2(fd, tot.c_str(), tot.length());
}

#endif 

