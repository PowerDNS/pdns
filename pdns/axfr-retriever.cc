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

#include "axfr-retriever.hh"
#include "arguments.hh"
#include "dns_random.hh"
#include "utility.hh"
#include "resolver.hh"
#include "query-local-address.hh"

using pdns::resolver::parseResult;

AXFRRetriever::AXFRRetriever(const ComboAddress& remote,
                             const DNSName& domain,
                             const TSIGTriplet& tt, 
                             const ComboAddress* laddr,
                             size_t maxReceivedBytes,
                             uint16_t timeout)
  : d_tsigVerifier(tt, remote, d_trc), d_receivedBytes(0), d_maxReceivedBytes(maxReceivedBytes)
{
  ComboAddress local;
  if (laddr != nullptr) {
    local = ComboAddress(*laddr);
  } else {
    if (!pdns::isQueryLocalAddressFamilyEnabled(remote.sin4.sin_family)) {
      throw ResolverException("Unable to determine source address for AXFR request to " + remote.toStringWithPort() + " for " + domain.toLogString() + ". Address family is not configured for outgoing queries");
    }
    local = pdns::getQueryLocalAddress(remote.sin4.sin_family, 0);
  }
  d_sock = -1;
  try {
    d_sock = makeQuerySocket(local, false); // make a TCP socket
    if (d_sock < 0)
      throw ResolverException("Error creating socket for AXFR request to "+d_remote.toStringWithPort());
    d_buf = shared_array<char>(new char[65536]);
    d_remote = remote; // mostly for error reporting
    this->connect(timeout);
    d_soacount = 0;
  
    vector<uint8_t> packet;
    DNSPacketWriter pw(packet, domain, QType::AXFR);
    pw.getHeader()->id = dns_random_uint16();
  
    if(!tt.name.empty()) {
      if (tt.algo == DNSName("hmac-md5"))
        d_trc.d_algoName = tt.algo + DNSName("sig-alg.reg.int");
      else
        d_trc.d_algoName = tt.algo;
      d_trc.d_time = time(0);
      d_trc.d_fudge = 300;
      d_trc.d_origID=ntohs(pw.getHeader()->id);
      d_trc.d_eRcode=0;
      addTSIG(pw, d_trc, tt.name, tt.secret, "", false);
    }
  
    uint16_t replen=htons(packet.size());
    Utility::iovec iov[2];
    iov[0].iov_base=reinterpret_cast<char*>(&replen);
    iov[0].iov_len=2;
    iov[1].iov_base=packet.data();
    iov[1].iov_len=packet.size();
  
    int ret=Utility::writev(d_sock, iov, 2);
    if(ret < 0)
      throw ResolverException("Error sending question to "+d_remote.toStringWithPort()+": "+stringerror());
    if(ret != (int)(2+packet.size())) {
      throw ResolverException("Partial write on AXFR request to "+d_remote.toStringWithPort());
    }
  
    int res = waitForData(d_sock, timeout, 0);
    
    if(!res)
      throw ResolverException("Timeout waiting for answer from "+d_remote.toStringWithPort()+" during AXFR");
    if(res<0)
      throw ResolverException("Error waiting for answer from "+d_remote.toStringWithPort()+": "+stringerror());
  }
  catch(...) {
    if(d_sock >= 0)
      close(d_sock);
    d_sock = -1;
    throw;
  }
}

AXFRRetriever::~AXFRRetriever()
{
  close(d_sock);
}



int AXFRRetriever::getChunk(Resolver::res_t &res, vector<DNSRecord>* records, uint16_t timeout) // Implementation is making sure RFC2845 4.4 is followed.
{
  if(d_soacount > 1)
    return false;

  // d_sock is connected and is about to spit out a packet
  int len=getLength(timeout);
  if(len<0)
    throw ResolverException("EOF trying to read axfr chunk from remote TCP client");

  if (d_maxReceivedBytes > 0 && (d_maxReceivedBytes - d_receivedBytes) < (size_t) len)
    throw ResolverException("Reached the maximum number of received bytes during AXFR");

  timeoutReadn(len, timeout);

  d_receivedBytes += (uint16_t) len;

  MOADNSParser mdp(false, d_buf.get(), len);

  int err = mdp.d_header.rcode;

  if(err) {
    throw ResolverException("AXFR chunk error: " + RCode::to_s(err));
  }

  try {
    d_tsigVerifier.check(std::string(d_buf.get(), len), mdp);
  }
  catch(const std::runtime_error& re) {
    throw ResolverException(re.what());
  }

  if(!records) {
    err = parseResult(mdp, DNSName(), 0, 0, &res);

    if (!err) {
      for(const auto& answer :  mdp.d_answers)
        if (answer.first.d_type == QType::SOA)
          d_soacount++;
    }
  }
  else {
    records->clear();
    records->reserve(mdp.d_answers.size());

    for(auto& r: mdp.d_answers) {
      if (r.first.d_type == QType::SOA) {
        d_soacount++;
      }

      records->push_back(std::move(r.first));
    }
  }

  return true;
}

void AXFRRetriever::timeoutReadn(uint16_t bytes, uint16_t timeoutsec)
{
  time_t start=time(nullptr);
  int n=0;
  int numread;
  while(n<bytes) {
    int res=waitForData(d_sock, timeoutsec-(time(nullptr)-start));
    if(res<0)
      throw ResolverException("Reading data from remote nameserver over TCP: "+stringerror());
    if(!res)
      throw ResolverException("Timeout while reading data from remote nameserver over TCP");

    numread=recv(d_sock, d_buf.get()+n, bytes-n, 0);
    if(numread<0)
      throw ResolverException("Reading data from remote nameserver over TCP: "+stringerror());
    if(numread==0)
      throw ResolverException("Remote nameserver closed TCP connection");
    n+=numread;
  }
}

void AXFRRetriever::connect(uint16_t timeout)
{
  setNonBlocking( d_sock );

  int err;

  if((err=::connect(d_sock,(struct sockaddr*)&d_remote, d_remote.getSocklen()))<0 && errno!=EINPROGRESS) {
    try {
      closesocket(d_sock);
    }
    catch(const PDNSException& e) {
      d_sock=-1;
      throw ResolverException("Error closing AXFR socket after connect() failed: "+e.reason);
    }

    throw ResolverException("connect: "+stringerror());
  }

  if(!err)
    goto done;

  err=waitForRWData(d_sock, false, timeout, 0); // wait for writeability
  
  if(!err) {
    try {
      closesocket(d_sock); // timeout
    }
    catch(const PDNSException& e) {
      d_sock=-1;
      throw ResolverException("Error closing AXFR socket after timeout: "+e.reason);
    }

    d_sock=-1;
    errno=ETIMEDOUT;
    
    throw ResolverException("Timeout connecting to server");
  }
  else if(err < 0) {
    throw ResolverException("Error connecting: "+stringerror());
  }
  else {
    Utility::socklen_t len=sizeof(err);
    if(getsockopt(d_sock, SOL_SOCKET,SO_ERROR,(char *)&err,&len)<0)
      throw ResolverException("Error connecting: "+stringerror()); // Solaris

    if(err)
      throw ResolverException("Error connecting: "+string(strerror(err)));
  }
  
 done:
  setBlocking( d_sock );
  // d_sock now connected
}

int AXFRRetriever::getLength(uint16_t timeout)
{
  timeoutReadn(2, timeout);
  return (unsigned char)d_buf[0]*256+(unsigned char)d_buf[1];
}

