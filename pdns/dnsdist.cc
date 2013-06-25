/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2013  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include <netinet/tcp.h>
#include <boost/array.hpp>
#include <boost/program_options.hpp>
#include <boost/foreach.hpp>

/* syntax: dnsdist 8.8.8.8 8.8.4.4 208.67.222.222 208.67.220.220
   Added downstream server 8.8.8.8:53
   Added downstream server 8.8.4.4:53
   Added downstream server 208.67.222.222:53
   Added downstream server 208.67.220.220:53
   Listening on [::]:53

   And you are in business!
 */

StatBag S;
namespace po = boost::program_options;
po::variables_map g_vm;

bool g_verbose;
AtomicCounter g_pos, g_timeouts;

int Socket(int family, int type, int flags)
{
  int ret = socket(family, type, flags);
  if(ret < 0)
    throw runtime_error((boost::format("creating socket of type %d: %s") % family % strerror(errno)).str());
  return ret;
}

int Connect(int sockfd, const ComboAddress& remote)
{
  int ret = connect(sockfd, (struct sockaddr*)&remote, remote.getSocklen());
  if(ret < 0)
    throw runtime_error((boost::format("connecting socket to %s: %s") % remote.toStringWithPort() % strerror(errno)).str());
  return ret;
}

int Bind(int sockfd, const ComboAddress& local)
{
  int ret = bind(sockfd, (struct sockaddr*)&local, local.getSocklen());
  if(ret < 0)
    throw runtime_error((boost::format("binding socket to %s: %s") % local.toStringWithPort() % strerror(errno)).str());
  return ret;
}

/* the grand design. Per socket we listen on for incoming queries there is one thread.
   Then we have a bunch of connected sockets for talking to downstream servers. 
   We send directly to those sockets.

   For the return path, per downstream server we have a thread that listens to responses.

   Per socket there is an array of 2^16 states, when we send out a packet downstream, we note
   there the original requestor and the original id. The new ID is the offset in the array.

   When an answer comes in on a socket, we look up the offset by the id, and lob it to the 
   original requestor.

   IDs are assigned by atomic increments of the socket offset.
 */

struct IDState
{
  uint16_t origID;
  ComboAddress origRemote;
  int origFD;
};

struct SocketState
{
  int fd;
  pthread_t tid;
  ComboAddress remote;
  vector<IDState> idStates;
  AtomicCounter idOffset;
};

SocketState* g_socketstates;
unsigned int g_numremotes;

void* responderThread(void *p)
{
  SocketState* state = (SocketState*)p;
  if(g_verbose)
    cout << "Added downstream server "<<state->remote.toStringWithPort()<<endl;
  char packet[65536];

  struct dnsheader* dh = (struct dnsheader*)packet;
  int len;
  for(;;) {
    len = recv(state->fd, packet, sizeof(packet), 0);
    if(len < 0)
      continue;
    IDState* ids = &state->idStates[dh->id];
    if(ids->origFD < 0)
      continue;
    dh->id = ids->origID;
    sendto(ids->origFD, packet, len, 0, (struct sockaddr*)&ids->origRemote, ids->origRemote.getSocklen());
    if(g_verbose)
      cout << "Got answer from "<<state->remote.toStringWithPort()<<", relayed to "<<ids->origRemote.toStringWithPort()<<endl;

    ids->origFD = -1;
  }
  return 0;
}

struct ClientState
{
  ComboAddress local;
  int fd;
};

// listens to incoming queries, sends out to downstream servers
void* clientThread(void* p)
{
  ClientState* cs = (ClientState*) p;
  if(g_verbose)
    cout<<"Listening on "<<cs->local.toStringWithPort()<<endl;

  ComboAddress remote;
  remote.sin4.sin_family = cs->local.sin4.sin_family;
  socklen_t socklen = cs->local.getSocklen();
  
  char packet[1500];
  struct dnsheader* dh = (struct dnsheader*) packet;
  int len;

  for(;;) {
    len = recvfrom(cs->fd, packet, sizeof(packet), 0, (struct sockaddr*) &remote, &socklen);
    if(len < 0)
      continue;
    
    SocketState& ss = g_socketstates[(g_pos++) % g_numremotes];
    unsigned int idOffset = ss.idOffset++;
    IDState* ids = &ss.idStates[idOffset];
    ids->origFD = cs->fd;
    ids->origID = dh->id;
    ids->origRemote = remote;
    dh->id = idOffset;
    
    send(ss.fd, packet, len, 0);
    if(g_verbose)
      cout<<"Got query from "<<remote.toStringWithPort()<<",relayed to "<<ss.remote.toStringWithPort()<<endl;
  }
  return 0;
}

int main(int argc, char** argv)
try
{
  po::options_description desc("Allowed options"), hidden, alloptions;
  desc.add_options()
    ("help,h", "produce help message")
    ("local", po::value<vector<string> >(), "Listen on which address")
    ("verbose,v", "be verbose");
    
  hidden.add_options()
    ("remotes", po::value<vector<string> >(), "remote-host");

  alloptions.add(desc).add(hidden); 

  po::positional_options_description p;
  p.add("remotes", -1);

  po::store(po::command_line_parser(argc, argv).options(alloptions).positional(p).run(), g_vm);
  po::notify(g_vm);
  
  if(g_vm.count("help")) {
    cout << desc<<endl;
    exit(EXIT_SUCCESS);
  }

  g_verbose=g_vm.count("verbose");
  
  if(!g_vm.count("remotes")) {
    cerr<<"Need to specify at least one remote address"<<endl;
    cout<<desc<<endl;
    exit(EXIT_FAILURE);
  }
  vector<string> remotes = g_vm["remotes"].as<vector<string> >();

  g_numremotes = remotes.size();
  g_socketstates = new SocketState[g_numremotes];
  int pos=0;
  BOOST_FOREACH(const string& remote, remotes) {
    SocketState& ss = g_socketstates[pos++];
 
    ss.remote = ComboAddress(remote, 53);
    
    ss.fd = Socket(ss.remote.sin4.sin_family, SOCK_DGRAM, 0);
    Connect(ss.fd, ss.remote);

    ss.idStates.resize(65536);
    BOOST_FOREACH(IDState& ids, ss.idStates) {
      ids.origFD = -1;
    }

    pthread_create(&ss.tid, 0, responderThread, (void*)&ss);
  }

  pthread_t tid;
  vector<string> locals;
  if(g_vm.count("local"))
    locals = g_vm["local"].as<vector<string> >();
  else
    locals.push_back("::");

  BOOST_FOREACH(const string& local, locals) {
    ClientState* cs = new ClientState;
    cs->local= ComboAddress(local, 53);
    cs->fd = Socket(cs->local.sin4.sin_family, SOCK_DGRAM, 0);
    if(cs->local.sin4.sin_family == AF_INET6) {
      int val = 1;
      setsockopt(cs->fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));
    }
    Bind(cs->fd, cs->local);
    
    pthread_create(&tid, 0, clientThread, (void*) cs);
  }

  void* status;
  pthread_join(tid, &status);

}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
catch(AhuException &ae)
{
  cerr<<"Fatal: "<<ae.reason<<endl;
}
