#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "remotebackend.hh"
#ifndef UNIX_PATH_MAX 
#define UNIX_PATH_MAX 108
#endif

UnixsocketConnector::UnixsocketConnector(std::map<std::string,std::string> options) {
  if (options.count("path") == 0) {
    L<<Logger::Error<<"Cannot find 'path' option in connection string"<<endl;
    throw PDNSException();
  } 
  this->timeout = 2000;
  if (options.find("timeout") != options.end()) { 
    this->timeout = std::stoi(options.find("timeout")->second);
  }
  this->path = options.find("path")->second;
  this->options = options;
  this->connected = false;
  this->fd = -1;
}

UnixsocketConnector::~UnixsocketConnector() {
  if (this->connected) {
     L<<Logger::Info<<"closing socket connection"<<endl;
     close(fd);
  }
}

int UnixsocketConnector::send_message(const Json& input) {
  auto data = input.dump() + "\n";
  int rv = this->write(data);
  if (rv == -1)
    return -1;
  return rv;
}

int UnixsocketConnector::recv_message(Json& output) {
  int rv,nread;
  std::string s_output,err;

  struct timeval t0,t;

  nread = 0;
  gettimeofday(&t0, NULL);
  memcpy(&t,&t0,sizeof(t0));
  s_output = "";       

  while((t.tv_sec - t0.tv_sec)*1000 + (t.tv_usec - t0.tv_usec)/1000 < this->timeout) { 
    int avail = waitForData(this->fd, 0, this->timeout * 500); // use half the timeout as poll timeout
    if (avail < 0) // poll error
      return -1;
    if (avail == 0) { // timeout
      gettimeofday(&t, NULL);
      continue;
    }

    std::string temp;
    temp.clear();

    rv = this->read(temp);
    if (rv == -1) 
      return -1;

    if (rv>0) {
      nread += rv;
      s_output.append(temp);
      // see if it can be parsed
      output = Json::parse(s_output, err);
      if (output != nullptr) return s_output.size();
    }
    gettimeofday(&t, NULL);
  }

  close(fd);
  connected = false; // we need to reconnect
  return -1;
}

ssize_t UnixsocketConnector::read(std::string &data) {
  ssize_t nread;
  char buf[1500] = {0};

  reconnect();
  if (!connected) return -1;
  nread = ::read(this->fd, buf, sizeof buf);

  // just try again later...
  if (nread==-1 && errno == EAGAIN) return 0;

  if (nread==-1 || nread==0) {
    connected = false;
    close(fd);
    return -1;
  }

  data.append(buf, nread);
  return nread;
}

ssize_t UnixsocketConnector::write(const std::string &data) {
  ssize_t nwrite, nbuf;
  size_t pos;
  char buf[1500];

  reconnect();
  if (!connected) return -1;
  pos = 0;
  nwrite = 0;
  while(pos < data.size()) {
    nbuf = data.copy(buf, sizeof buf, pos); // copy data and write
    nwrite = ::write(fd, buf, nbuf);
    pos = pos + sizeof(buf);
    if (nwrite < 1) {
      connected = false;
      close(fd);
      return -1;
    }
  }
  return nwrite;
}

void UnixsocketConnector::reconnect() {
  struct sockaddr_un sock;
  int rv;

  if (connected) return; // no point reconnecting if connected...
  connected = true;

  L<<Logger::Info<<"Reconnecting to backend" << std::endl;
  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
     connected = false;
     L<<Logger::Error<<"Cannot create socket: " << strerror(errno) << std::endl;;
     return;
  }

  if (makeUNsockaddr(path, &sock)) {
     L<<Logger::Error<<"Unable to create UNIX domain socket: Path '"<<path<<"' is not a valid UNIX socket path."<<std::endl;
     return;
  }

  rv = connect(fd, reinterpret_cast<struct sockaddr*>(&sock), sizeof sock);

  if (rv != 0 && errno != EISCONN && errno != 0) {
     L<<Logger::Error<<"Cannot connect to socket: " << strerror(errno) << std::endl;
     close(fd);
     connected = false;
     return;
  }
  // send initialize

  Json::array parameters;
  Json msg = Json(Json::object{
    { "method", "initialize" },
    { "parameters", Json(options) },
  });

  this->send(msg);
  msg = nullptr;
  if (this->recv(msg) == false) {
     L<<Logger::Warning << "Failed to initialize backend" << std::endl;
     close(fd);
     this->connected = false;
  }
}
