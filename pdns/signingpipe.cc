#include "signingpipe.hh"
#include "misc.hh"
#include <poll.h>
#include <boost/foreach.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>

struct StartHelperStruct
{
  StartHelperStruct(ChunkedSigningPipe* csp, int id, int fd) : d_csp(csp), d_id(id), d_fd(fd){}
  ChunkedSigningPipe* d_csp;
  int d_id;
  int d_fd;
};

void* ChunkedSigningPipe::helperWorker(void* p)
try
{
  StartHelperStruct shs=*(StartHelperStruct*)p;
  delete (StartHelperStruct*)p;
  
  shs.d_csp->worker(shs.d_id, shs.d_fd);
  return 0;
}
catch(std::exception& e) {
  cerr<<"Signing thread died with error "<<e.what()<<endl;
  return 0;
}

ChunkedSigningPipe::ChunkedSigningPipe(const std::string& signerName, bool mustSign, const pdns::string& servers, unsigned int workers) 
  : d_queued(0), d_outstanding(0), d_signer(signerName), d_maxchunkrecords(100), d_numworkers(workers), d_tids(d_numworkers),
    d_mustSign(mustSign), d_final(false)
{
  d_rrsetToSign = new rrset_t;
  d_chunks.push_back(vector<DNSResourceRecord>());
  if(!d_mustSign)
    return;
  
  int fds[2];
  
  ServiceTuple st;
  ComboAddress remote;
  if(!servers.empty()) {
    st.port=2000;
    parseService(servers, st);
    remote=ComboAddress(st.host, st.port);
  }
  
  for(unsigned int n=0; n < d_numworkers; ++n) {
    if(!servers.empty()) {
      fds[0] = socket(AF_INET, SOCK_STREAM, 0);
      fds[1] = -1;
      
      if(connect(fds[0], (struct sockaddr*)&remote, remote.getSocklen()) < 0)
        unixDie("Connecting to signing server");
      
      //int tmp=1;
      //setsockopt(fds[0], SOL_TCP, TCP_NODELAY, &tmp, sizeof(tmp));
    }
    else {
      if(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) 
        throw runtime_error("Unable to create communication socket in for ChunkedSigningPipe");
      pthread_create(&d_tids[n], 0, helperWorker, (void*) new StartHelperStruct(this, n, fds[1]));
#if 0
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
    }
  
    d_sockets.push_back(fds[0]);
    Utility::setNonBlocking(fds[0]);
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
        cerr<<"Got decent EOF on "<<fd<<endl;
        return 0;
      }
    }
      
    if(res < 0) {
      if(errno == EAGAIN || errno == EINTR) {
        if(pos==0)
          return 0;
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

pair<vector<int>, vector<int> > ChunkedSigningPipe::waitForRW(bool rd, bool wr, int seconds)
{
  struct pollfd pfds[d_sockets.size()];
  
  for(unsigned int n = 0; n < d_sockets.size(); ++n) {
    
    memset(&pfds[n], 0, sizeof(pfds[n]));
    pfds[n].fd = d_sockets[n];
    if(!d_eof.count(n)) {
      if(rd)
        pfds[n].events |= POLLIN;
      if(wr)
        pfds[n].events |= POLLOUT;
    }
  }
  
  int res = poll(pfds, d_sockets.size(), seconds * 1000); // negative = infinite
  if(res < 0)
    unixDie("polling for activity from signers");
  pair<vector<int>, vector<int> > vects;
  for(unsigned int n = 0; n < d_sockets.size(); ++n) 
    if(pfds[n].revents & POLLIN)
      vects.first.push_back(pfds[n].fd);
    else if(pfds[n].revents & POLLOUT)
      vects.second.push_back(pfds[n].fd);
  
  return vects;
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
  
  bool wantRead, wantWrite;
  
  wantWrite = !d_rrsetToSign->empty();
  wantRead = d_outstanding | wantWrite;  // if we wrote, we want to read
  
  pair<vector<int>, vector<int> > rwVect;
  
  waitForWrite:;
  if(d_final) {
    if(!d_outstanding)
      return;
    // cerr<<"Setting timeout to infinite, outstanding = " <<d_outstanding<<endl;
  }
  rwVect = waitForRW(wantRead, wantWrite, d_final ? -1 : 0);
  random_shuffle(rwVect.second.begin(), rwVect.second.end());
  
  if(wantWrite && !rwVect.second.empty()) {
    //string msg = convertDNSRRVectorToPBString(*d_rrsetToSign);
    //writeLStringToSocket(*rwVect.second.begin(), msg);
    writen2(*rwVect.second.begin(), &d_rrsetToSign, sizeof(d_rrsetToSign));
    d_rrsetToSign = new rrset_t;
    d_outstanding++;
    d_queued++;
  } // if wantWrite && we couldn't, we must try again after reading a bit

  string str;
  while(d_outstanding) {
    bool gotSomething=false;
    chunk_t* chunk;
    BOOST_FOREACH(int fd, rwVect.first) {
      if(d_eof.count(fd))
        continue;
      int res = readn(fd, &chunk, sizeof(chunk));
      if(!res) {
        d_eof.insert(fd);
        break;
      }
      if(res < 0)
        unixDie("Error reading signed chunk from thread");
        
      --d_outstanding;
      d_chunks.back().insert(d_chunks.back().end(), chunk->begin(), chunk->end());
      delete chunk;
      
      if(d_chunks.back().size() > d_maxchunkrecords) {
        d_chunks.push_back(vector<DNSResourceRecord>()); // we filled a chunk, and have no need to queue further now
        break;
      }    
    }
    if(!gotSomething)
        break;
    if(d_chunks.back().empty()) // this means we've read a full chunk and should cut it out already
      break;
  }
  
  if(wantWrite && !d_rrsetToSign->empty()) { // we still have something to write, and should try again
    wantRead = false;
    goto waitForWrite;
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
    
    addRRSigs(dk, db, d_signer, *chunk);
    ++d_signed;
    
    writen2(fd, &chunk, sizeof(chunk));
  }
  close(fd);
}
catch(...)
{
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
      cerr<<"shutdown of "<<fd<<endl;
      // writeLStringToSocket(fd, string()); // empty string == EOF
    }
  }
  if(d_final)
    flushToSign(); // should help us wait
  vector<DNSResourceRecord> front=d_chunks.front();
  d_chunks.pop_front();
  if(d_chunks.empty())
    d_chunks.push_back(vector<DNSResourceRecord>());
  if(d_final && front.empty())
    cerr<<"getChunk returning empty in final"<<endl;
  return front;
}
