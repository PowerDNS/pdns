#include "remotebackend.hh"
#include <sys/socket.h>
#include <pdns/lock.hh> 
#include <unistd.h>
#include <sys/select.h>
#include <fcntl.h>

#ifndef UNIX_PATH_MAX 
#define UNIX_PATH_MAX 108
#endif


// Singleton class to maintain client connection
// via single unix socket connection
static int n_unix_socket_connection;
static pthread_mutex_t unix_build_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t unix_mutex = PTHREAD_MUTEX_INITIALIZER;
class UnixsocketConnection {
  public:
    UnixsocketConnection(const std::string &path)
    {
      this->path = path;
      connected = false;
    };

    ~UnixsocketConnection() {
      L<<Logger::Info<<"closing socket connection"<<endl;
      close(fd);
    };

    ssize_t read(std::string &data) { 
        ssize_t nread;
        char buf[1500] = {0};
        Lock scoped_lock(&unix_mutex); 

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
    };

    ssize_t write(const std::string &data) { 
        ssize_t nwrite, nbuf;
        char buf[1500];
        Lock scoped_lock(&unix_mutex); 

        reconnect();
        if (!connected) return -1;
        nbuf = data.copy(buf, sizeof buf); // copy data and write
        nwrite = ::write(fd, buf, nbuf);
        if (nwrite == -1) {
          connected = false;
          close(fd);
          return -1;
        }
        return nwrite;
    };

  private:
    int fd;
    bool connected;
    std::string path;

    void reconnect() {
       struct sockaddr_un sock;
       struct timeval tv;
       fd_set rd;

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
	 tv.tv_sec = 0;
         tv.tv_usec = 500;
         FD_ZERO(&rd);
         FD_SET(fd, &rd);
         select(fd+1,&rd,NULL,NULL,&tv); // wait a moment
       };
       if (errno != EISCONN && errno != 0) {
          L<<Logger::Error<<"Cannot connect to socket: " << strerror(errno) << std::endl;
          close(fd);
          connected = false;
          return;
       }
    };
};

static UnixsocketConnection *unix_socket_connection;

UnixsocketConnector::UnixsocketConnector(std::map<std::string,std::string> options) {
     Lock scoped_lock(&unix_build_mutex);

     if (unix_socket_connection == NULL) {
       Json::Value init,res;
       unix_socket_connection = new UnixsocketConnection(options.find("path")->second);
       n_unix_socket_connection = 1;
       init["method"] = "initialize";
       init["parameters"] = Json::Value();
       for(std::map<std::string,std::string>::iterator i = options.begin(); i != options.end(); i++)
         init["parameters"][i->first] = i->second;
       this->send(init);
       if (this->recv(res) == false)
          L<<Logger::Warning << "Failed to initialize backend" << std::endl;
     } else {
       n_unix_socket_connection++;
     }
}

UnixsocketConnector::~UnixsocketConnector() {
     Lock scoped_lock(&unix_build_mutex);
 
     n_unix_socket_connection--;
     if (n_unix_socket_connection == 0) {
       delete unix_socket_connection;
       unix_socket_connection = NULL;
     }
}

int UnixsocketConnector::send_message(const Json::Value &input) {
        std::string data;
        Json::FastWriter writer;
        int rv;
        data = writer.write(input);
        //i make sure we got nothing waiting there.
        std::string temp;
        while(unix_socket_connection->read(temp)>0) { temp = ""; }
        rv = unix_socket_connection->write(data);
        if (rv == -1)
            throw AhuException("Failed to write to socket");
        return rv;
}

int UnixsocketConnector::recv_message(Json::Value &output) {
        int rv,nread;
        std::string s_output;
        Json::Reader r;
        time_t t0;

        nread = 0;
        t0 = time(NULL);
        s_output = "";       
 
        while(time(NULL) - t0 < 2) { // 2 second timeout 
          std::string temp;
          rv = unix_socket_connection->read(temp);
          if (rv == -1) 
            throw AhuException("Failed to read from socket");

          if (rv>0) {
            nread += rv;
            s_output.append(temp);
            if (r.parse(s_output,output)==true) {
               return nread;
            }
          }
        }

        return -1;
}
