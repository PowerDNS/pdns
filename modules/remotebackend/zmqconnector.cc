#include "remotebackend.hh"
#ifdef REMOTEBACKEND_ZEROMQ

#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <boost/foreach.hpp>
#include <sstream>
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

ZeroMQConnector::ZeroMQConnector(std::map<std::string,std::string> options) {
  rapidjson::Value val;
  rapidjson::Document init,res;
  int opt=0;

  // lookup timeout, target and stuff
  if (options.count("endpoint") == 0) {
    L<<Logger::Error<<"Cannot find 'endpoint' option in connection string"<<endl;
    throw PDNSException("Cannot find 'endpoint' option in connection string");
  }
  this->d_endpoint = options.find("endpoint")->second;
  this->d_options = options;
  this->d_timeout=2000;

  if (options.find("timeout") != options.end()) {
     this->d_timeout = boost::lexical_cast<int>(options.find("timeout")->second);
  }

  d_ctx = zmq_init(2);
  d_sock = zmq_socket(this->d_ctx, ZMQ_REQ);
  zmq_setsockopt(d_sock, ZMQ_LINGER, &opt, sizeof(opt));

  if(zmq_connect(this->d_sock, this->d_endpoint.c_str()) < 0)
  {
    L<<Logger::Error<<"zmq_connect() failed"<< zmq_strerror(errno)<<std::endl;;
    throw PDNSException("Cannot find 'endpoint' option in connection string");
  }

  init.SetObject();
  val = "initialize";

  init.AddMember("method",val, init.GetAllocator());
  val.SetObject();
  init.AddMember("parameters", val, init.GetAllocator());

  for(std::map<std::string,std::string>::iterator i = options.begin(); i != options.end(); i++) {
    val = i->second.c_str();
    init["parameters"].AddMember(i->first.c_str(), val, init.GetAllocator());
  }

  this->send(init);
  if (this->recv(res)==false) {
    L<<Logger::Error<<"Failed to initialize zeromq"<<std::endl;
    throw PDNSException("Failed to initialize zeromq");
  } 
};

ZeroMQConnector::~ZeroMQConnector() {
  zmq_close(this->d_sock);
  zmq_term(this->d_ctx);
};

int ZeroMQConnector::send_message(const rapidjson::Document &input) {
   std::string line;
   line = makeStringFromDocument(input);
   zmq_msg_t message;

   zmq_msg_init_size(&message, line.size()+1);
   line.copy(reinterpret_cast<char*>(zmq_msg_data(&message)), line.size());
   ((char *)zmq_msg_data(&message))[line.size()] = '\0';

   try {
     zmq_pollitem_t item;
     item.socket = d_sock;
     item.events = ZMQ_POLLOUT;
     // poll until it's sent or timeout is spent. try to leave 
     // leave few cycles for read. just in case. 
     for(d_timespent = 0; d_timespent < d_timeout-5; d_timespent++) {
       if (zmq_poll(&item, 1, 1)>0) {
         if(zmq_msg_send(&message, this->d_sock, 0) == -1) {
           // message was not sent
           L<<Logger::Error<<"Cannot send to " << this->d_endpoint << ": " << zmq_strerror(errno)<<std::endl;
         } else
           return line.size();
       }
     }
   } catch (std::exception &ex) {
     L<<Logger::Error<<"Cannot send to " << this->d_endpoint << ": " << ex.what()<<std::endl;
     throw PDNSException(ex.what());
   }

   return 0;
}

int ZeroMQConnector::recv_message(rapidjson::Document &output) {
   int rv = 0;
   // try to receive message
   zmq_pollitem_t item;
   rapidjson::GenericReader<rapidjson::UTF8<> , rapidjson::MemoryPoolAllocator<> > r;
   zmq_msg_t message;

   item.socket = d_sock;
   item.events = ZMQ_POLLIN;

   try {
     // do zmq::poll few times 
     // d_timespent should always be initialized by send_message, recv should never
     // be called without send first.
     for(; d_timespent < d_timeout; d_timespent++) {
       if (zmq_poll(&item, 1, 1)>0) {
         // we have an event
         if ((item.revents & ZMQ_POLLIN) == ZMQ_POLLIN) {
           char *data;
           size_t msg_size;
           zmq_msg_init(&message);
           // read something
           if(zmq_msg_recv(&message, this->d_sock, ZMQ_NOBLOCK)>0) {
               msg_size = zmq_msg_size(&message);
               data = new char[msg_size+1];
               memcpy(data, zmq_msg_data(&message), msg_size);
               data[msg_size] = '\0';
               zmq_msg_close(&message);

               rapidjson::StringStream ss(data);
               output.ParseStream<0>(ss);
               delete[] data;

               if (output.HasParseError() == false)
                 rv = msg_size;
               else 
                 L<<Logger::Error<<"Cannot parse JSON reply from " << this->d_endpoint<<std::endl;
               break;
             } else if (errno == EAGAIN) { continue; // try again }
             } else {
                break; 
             } 
          }
        }
     }
   } catch (std::exception &ex) {
     L<<Logger::Error<<"Cannot receive from " << this->d_endpoint << ": " << ex.what()<<std::endl;
     throw PDNSException(ex.what());
   }

   return rv;
}

#endif
