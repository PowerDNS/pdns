#include "remotebackend.hh"
#include <sys/socket.h>
#include <pdns/lock.hh>
#include <unistd.h>
#include <fcntl.h>
#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

UnixsocketConnector::UnixsocketConnector(std::map<std::string,std::string> options) {
   if (options.count("path") == 0) {
     L<<Logger::Error<<"Cannot find 'path' option in connection string"<<endl;
     throw new AhuException();
   }
   this->timeout = 2000;
   if (options.find("timeout") != options.end()) {
     this->timeout = boost::lexical_cast<int>(options.find("timeout")->second);
   }
   this->path = options.find("path")->second;
   this->options = options;
   this->connected = false;
}

UnixsocketConnector::~UnixsocketConnector() {
   if (this->connected) {
      L<<Logger::Info<<"closing socket connection"<<endl;
      close(fd);
   }
}

int UnixsocketConnector::send_message(const rapidjson::Document &input) {
        std::string data;
        int rv;
        data = makeStringFromDocument(input);
        data = data + "\n";
        rv = this->write(data);
        if (rv == -1)
          return -1;
        return rv;
}

int UnixsocketConnector::recv_message(rapidjson::Document &output) {
        int rv,nread;
        std::string s_output;
        rapidjson::GenericReader<rapidjson::UTF8<> , rapidjson::MemoryPoolAllocator<> > r;

        struct timeval t0,t;

        nread = 0;
        gettimeofday(&t0, NULL);
        memcpy(&t,&t0,sizeof(t0));
        s_output = "";

        while((t.tv_sec - t0.tv_sec)*1000 + (t.tv_usec - t0.tv_usec)/1000 < this->timeout) {
          std::string temp;
          temp.clear();

          rv = this->read(temp);
          if (rv == -1)
            return -1;

          if (rv>0) {
            nread += rv;
            s_output.append(temp);
            rapidjson::StringStream ss(s_output.c_str());
            output.ParseStream<0>(ss);
            if (output.HasParseError() == false)
              return s_output.size();
          }
          gettimeofday(&t, NULL);
        }

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

    if (nread==-1) {
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
      if (nwrite == -1) {
        connected = false;
        close(fd);
        return -1;
      }
    }
    return nwrite;
}

void UnixsocketConnector::reconnect() {
   struct sockaddr_un sock;
   rapidjson::Document init,res;
   rapidjson::Value val;

   if (connected) return; // no point reconnecting if connected...
   connected = true;

   L<<Logger::Info<<"Reconnecting to backend" << std::endl;
   fd = socket(AF_UNIX, SOCK_STREAM, 0);
   if (fd < 0) {
      connected = false;
      L<<Logger::Error<<"Cannot create socket: " << strerror(errno) << std::endl;;
      return;
   }
   sock.sun_family = AF_UNIX;
   memset(sock.sun_path, 0, UNIX_PATH_MAX);
   path.copy(sock.sun_path, UNIX_PATH_MAX, 0);
   fcntl(fd, F_SETFL, O_NONBLOCK, &fd);

   while(connect(fd, reinterpret_cast<struct sockaddr*>(&sock), sizeof sock)==-1 && (errno == EINPROGRESS)) {
     waitForData(fd, 0, 500);
   }

   if (errno != EISCONN && errno != 0) {
      L<<Logger::Error<<"Cannot connect to socket: " << strerror(errno) << std::endl;
      close(fd);
      connected = false;
      return;
   }
   // send initialize

   init.SetObject();
   val = "initialize";
   init.AddMember("method",val, init.GetAllocator());
   val.SetObject();
   init.AddMember("parameters", val, init.GetAllocator());

   for(std::map<std::string,std::string>::iterator i = options.begin(); i != options.end(); i++) {
     val = i->second.c_str();
     init["parameters"].AddMember(i->first.c_str(), val, init.GetAllocator());
   }

   this->send_message(init);
   if (this->recv_message(res) == false) {
      L<<Logger::Warning << "Failed to initialize backend" << std::endl;
      close(fd);
      this->connected = false;
   }
}

