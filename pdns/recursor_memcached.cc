#include <string>
#include "statbag.hh"
#include "iputils.hh"
#include "recursor_memcached.hh"
#include <boost/lexical_cast.hpp>

#include "namespaces.hh"
using boost::lexical_cast;

MemcachedCommunicator::MemcachedCommunicator(const std::string& servers)
{
  d_socket=socket(AF_INET, SOCK_DGRAM, 0);
  Utility::setCloseOnExec(d_socket);

  ComboAddress remote(servers, 11211);
  if(connect(d_socket, (struct sockaddr*)&remote, remote.getSocklen()) < 0)
    unixDie("connecting to remote memcached server '"+remote.toStringWithPort()+"'");
}

string MemcachedCommunicator::get(const std::string& key)
{
  cerr<<"Looking up: '"<<key<<"'\n";
  string message("get "+key+"\r\n");
  UDPHeader uh;
  uh.totalDgrams=htons(1);
  
  string packet((char*)&uh, sizeof(uh));
  packet+=message;
  
  if(send(d_socket, packet.c_str(), packet.length(), 0) < 0)
    unixDie("sending packet to remote Memcached server");

  char buffer[1500];

  int ret=recv(d_socket, buffer, sizeof(buffer), 0);
  if(ret <= 0) 
    unixDie("receiving packet from Memcached server");
  string response(buffer+sizeof(uh), ret-sizeof(uh));
  string::size_type pos = response.find('\n');
  if(pos == string::npos) 
    unixDie("Invalid response from memcached, no \\n");
  int flags, len;
  string value;
  if(response != "END\r\n") {
    char tmp[21];
    if(sscanf(response.c_str(),"VALUE %20s %d %d", tmp, &flags, &len)!=3) 
      throw runtime_error("Unable to parse memcached response '"+response+"'");
    
    value=string(response.c_str()+pos+1, len);
  }
  cerr<<"Returning: '"<<value<<"'\n";
  return value;

}

void MemcachedCommunicator::set(const std::string& key, const std::string& value)
{
  cerr<<"setting: '"<<key<<"' to '"<<value<<"'\n";
  string message("set "+key+" 0 0 "+lexical_cast<string>(value.length())+"\r\n"+value+"\r\n");
  cerr<<"Message is: '"<<message<<"'\n";
  UDPHeader uh;
  uh.totalDgrams=htons(1);
  
  string packet((char*)&uh, sizeof(uh));
  packet+=message;
  
  if(send(d_socket, packet.c_str(), packet.length(), 0) < 0)
    unixDie("sending packet to remote Memcached server");

  char buffer[1500];

  int ret=recv(d_socket, buffer, sizeof(buffer), 0);
  if(ret <= 0) 
    unixDie("receiving packet from Memcached server");
  string response(buffer+sizeof(uh), ret-sizeof(uh));
  cerr<<"Response: '"<<response<<"'\n";
}


#if 0
int main(int argc, char** argv)
{
  MemcachedCommunicator mc("127.0.0.1");
  
  cerr<<"Looking up key '"<<argv[1]<<"': '"<<mc.get(argv[1])<<"'"<<endl;

}
#endif
