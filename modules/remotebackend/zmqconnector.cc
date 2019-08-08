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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "remotebackend.hh"
#ifdef REMOTEBACKEND_ZEROMQ

ZeroMQConnector::ZeroMQConnector(std::map<std::string,std::string> options): d_ctx(std::unique_ptr<void, int(*)(void*)>(zmq_init(2), zmq_close)), d_sock(std::unique_ptr<void, int(*)(void*)>(zmq_socket(d_ctx.get(), ZMQ_REQ), zmq_close)) {
  int opt=0;

  // lookup timeout, target and stuff
  if (options.count("endpoint") == 0) {
    g_log<<Logger::Error<<"Cannot find 'endpoint' option in connection string"<<endl;
    throw PDNSException("Cannot find 'endpoint' option in connection string");
  }
  this->d_endpoint = options.find("endpoint")->second;
  this->d_options = options;
  this->d_timeout=2000;

  if (options.find("timeout") != options.end()) {
     this->d_timeout = std::stoi(options.find("timeout")->second);
  }

  zmq_setsockopt(d_sock.get(), ZMQ_LINGER, &opt, sizeof(opt));

  if(zmq_connect(this->d_sock.get(), this->d_endpoint.c_str()) < 0)
  {
    g_log<<Logger::Error<<"zmq_connect() failed"<< zmq_strerror(errno)<<std::endl;;
    throw PDNSException("Cannot find 'endpoint' option in connection string");
  }

  Json::array parameters;
  Json msg = Json(Json::object{
    { "method", "initialize" },
    { "parameters", Json(options) },
  });

  this->send(msg);
  msg = nullptr;
  if (this->recv(msg)==false) {
    g_log<<Logger::Error<<"Failed to initialize zeromq"<<std::endl;
    throw PDNSException("Failed to initialize zeromq");
  } 
};

ZeroMQConnector::~ZeroMQConnector() {}

int ZeroMQConnector::send_message(const Json& input) {
   auto line = input.dump();
   zmq_msg_t message;

   zmq_msg_init_size(&message, line.size()+1);
   line.copy(reinterpret_cast<char*>(zmq_msg_data(&message)), line.size());
   ((char *)zmq_msg_data(&message))[line.size()] = '\0';

   try {
     zmq_pollitem_t item;
     item.socket = d_sock.get();
     item.events = ZMQ_POLLOUT;
     // poll until it's sent or timeout is spent. try to leave 
     // leave few cycles for read. just in case. 
     for(d_timespent = 0; d_timespent < d_timeout-5; d_timespent++) {
       if (zmq_poll(&item, 1, 1)>0) {
         if(zmq_msg_send(&message, this->d_sock.get(), 0) == -1) {
           // message was not sent
           g_log<<Logger::Error<<"Cannot send to " << this->d_endpoint << ": " << zmq_strerror(errno)<<std::endl;
         } else
           return line.size();
       }
     }
   } catch (std::exception &ex) {
     g_log<<Logger::Error<<"Cannot send to " << this->d_endpoint << ": " << ex.what()<<std::endl;
     throw PDNSException(ex.what());
   }

   return 0;
}

int ZeroMQConnector::recv_message(Json& output) {
   int rv = 0;
   // try to receive message
   zmq_pollitem_t item;
   zmq_msg_t message;

   item.socket = d_sock.get();
   item.events = ZMQ_POLLIN;

   try {
     // do zmq::poll few times 
     // d_timespent should always be initialized by send_message, recv should never
     // be called without send first.
     for(; d_timespent < d_timeout; d_timespent++) {
       if (zmq_poll(&item, 1, 1)>0) {
         // we have an event
         if ((item.revents & ZMQ_POLLIN) == ZMQ_POLLIN) {
           string data;
           size_t msg_size;
           zmq_msg_init(&message);
           // read something
           if(zmq_msg_recv(&message, this->d_sock.get(), ZMQ_NOBLOCK)>0) {
               string err;
               msg_size = zmq_msg_size(&message);
               data.assign(reinterpret_cast<const char*>(zmq_msg_data(&message)), msg_size);
               zmq_msg_close(&message);
               output = Json::parse(data, err);
               if (output != nullptr)
                 rv = msg_size;
               else 
                 g_log<<Logger::Error<<"Cannot parse JSON reply from " << this->d_endpoint << ": " << err << endl;
               break;
             } else if (errno == EAGAIN) { continue; // try again }
             } else {
                break; 
             } 
          }
        }
     }
   } catch (std::exception &ex) {
     g_log<<Logger::Error<<"Cannot receive from " << this->d_endpoint << ": " << ex.what()<<std::endl;
     throw PDNSException(ex.what());
   }

   return rv;
}

#endif
