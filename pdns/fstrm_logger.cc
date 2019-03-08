#include <unistd.h>
#include <sys/un.h>

#include "config.h"
#include "fstrm_logger.hh"

#ifdef RECURSOR
#include "logger.hh"
#else
#include "dolog.hh"
#endif

#define DNSTAP_CONTENT_TYPE		"protobuf:dnstap.Dnstap"

#ifdef HAVE_FSTRM

FrameStreamLogger::FrameStreamLogger(const int family, const std::string& address, bool connect,
    const std::unordered_map<string,unsigned>& options): d_family(family), d_address(address)
{
  fstrm_res res;

  try {
    d_fwopt = fstrm_writer_options_init();
    if (!d_fwopt) {
      throw std::runtime_error("FrameStreamLogger: fstrm_writer_options_init failed.");
    }

    res = fstrm_writer_options_add_content_type(d_fwopt, DNSTAP_CONTENT_TYPE, sizeof(DNSTAP_CONTENT_TYPE) - 1);
    if (res != fstrm_res_success) {
      throw std::runtime_error("FrameStreamLogger: fstrm_writer_options_add_content_type failed: " + std::to_string(res));
    }

    if (d_family == AF_UNIX) {
      struct sockaddr_un local;
      if (makeUNsockaddr(d_address, &local)) {
        throw std::runtime_error("FrameStreamLogger: Unable to use '" + d_address + "', it is not a valid UNIX socket path.");
      }

      d_uwopt = fstrm_unix_writer_options_init();
      if (!d_uwopt) {
        throw std::runtime_error("FrameStreamLogger: fstrm_unix_writer_options_init failed.");
      }

      // void return, no error checking.
      fstrm_unix_writer_options_set_socket_path(d_uwopt, d_address.c_str());

      d_writer = fstrm_unix_writer_init(d_uwopt, d_fwopt);
      if (!d_writer) {
        throw std::runtime_error("FrameStreamLogger: fstrm_unix_writer_init() failed.");
      }
  #ifdef HAVE_FSTRM_TCP_WRITER_INIT
    } else if (family == AF_INET) {
      d_twopt = fstrm_tcp_writer_options_init();
      if (!d_twopt) {
        throw std::runtime_error("FrameStreamLogger: fstrm_tcp_writer_options_init failed.");
      }

      try {
        ComboAddress ca(d_address);

        // void return, no error checking.
        fstrm_tcp_writer_options_set_socket_address(d_twopt, ca.toString().c_str());
        fstrm_tcp_writer_options_set_socket_port(d_twopt, std::to_string(ca.getPort()).c_str());
      } catch (PDNSException &e) {
        throw std::runtime_error("FrameStreamLogger: Unable to use '" + d_address + "': " + e.reason);
      }

      d_writer = fstrm_tcp_writer_init(d_twopt, d_fwopt);
      if (!d_writer) {
        throw std::runtime_error("FrameStreamLogger: fstrm_tcp_writer_init() failed.");
      }
  #endif
    } else {
      throw std::runtime_error("FrameStreamLogger: family " + std::to_string(family) + " not supported");
    }

    d_iothropt = fstrm_iothr_options_init();
    if (!d_iothropt) {
      throw std::runtime_error("FrameStreamLogger: fstrm_iothr_options_init() failed.");
    }

    res = fstrm_iothr_options_set_queue_model(d_iothropt, FSTRM_IOTHR_QUEUE_MODEL_MPSC);
    if (res != fstrm_res_success) {
      throw std::runtime_error("FrameStreamLogger: fstrm_iothr_options_set_queue_model failed: " + std::to_string(res));
    }

    if (options.find("bufferHint") != options.end() && options.at("bufferHint")) {
      res = fstrm_iothr_options_set_buffer_hint(d_iothropt, options.at("bufferHint"));
      if (res != fstrm_res_success) {
        throw std::runtime_error("FrameStreamLogger: fstrm_iothr_options_set_buffer_hint failed: " + std::to_string(res));
      }
    }
    if (options.find("flushTimeout") != options.end() && options.at("flushTimeout")) {
      res = fstrm_iothr_options_set_flush_timeout(d_iothropt, options.at("flushTimeout"));
      if (res != fstrm_res_success) {
        throw std::runtime_error("FrameStreamLogger: fstrm_iothr_options_set_flush_timeout failed: " + std::to_string(res));
      }
    }
    if (options.find("inputQueueSize") != options.end() && options.at("inputQueueSize")) {
      res = fstrm_iothr_options_set_input_queue_size(d_iothropt, options.at("inputQueueSize"));
      if (res != fstrm_res_success) {
        throw std::runtime_error("FrameStreamLogger: fstrm_iothr_options_set_input_queue_size failed: " + std::to_string(res));
      }
    }
    if (options.find("outputQueueSize") != options.end() && options.at("outputQueueSize")) {
      res = fstrm_iothr_options_set_output_queue_size(d_iothropt, options.at("outputQueueSize"));
      if (res != fstrm_res_success) {
        throw std::runtime_error("FrameStreamLogger: fstrm_iothr_options_set_output_queue_size failed: " + std::to_string(res));
      }
    }
    if (options.find("queueNotifyThreshold") != options.end() && options.at("queueNotifyThreshold")) {
      res = fstrm_iothr_options_set_queue_notify_threshold(d_iothropt, options.at("queueNotifyThreshold"));
      if (res != fstrm_res_success) {
        throw std::runtime_error("FrameStreamLogger: fstrm_iothr_options_set_queue_notify_threshold failed: " + std::to_string(res));
      }
    }
    if (options.find("setReopenInterval") != options.end() && options.at("setReopenInterval")) {
      res = fstrm_iothr_options_set_reopen_interval(d_iothropt, options.at("setReopenInterval"));
      if (res != fstrm_res_success) {
        throw std::runtime_error("FrameStreamLogger: fstrm_iothr_options_set_reopen_interval failed: " + std::to_string(res));
      }
    }


    if (connect) {
      d_iothr = fstrm_iothr_init(d_iothropt, &d_writer);
      if (!d_iothr) {
        throw std::runtime_error("FrameStreamLogger: fstrm_iothr_init() failed.");
      }

      d_ioqueue = fstrm_iothr_get_input_queue(d_iothr);
      if (!d_ioqueue) {
        throw std::runtime_error("FrameStreamLogger: fstrm_iothr_get_input_queue() failed.");
      }
    }
  } catch (std::runtime_error &e) {
    this->cleanup();
    throw;
  }
}

void FrameStreamLogger::cleanup()
{
  if (d_iothr != nullptr) {
    fstrm_iothr_destroy(&d_iothr);
    d_iothr = nullptr;
  }
  if (d_iothropt != nullptr) {
    fstrm_iothr_options_destroy(&d_iothropt);
    d_iothropt = nullptr;
  }
  if (d_writer != nullptr) {
    fstrm_writer_destroy(&d_writer);
    d_writer = nullptr;
  }
  if (d_uwopt != nullptr) {
    fstrm_unix_writer_options_destroy(&d_uwopt);
    d_uwopt = nullptr;
  }
#ifdef HAVE_FSTRM_TCP_WRITER_INIT
  if (d_twopt != nullptr) {
    fstrm_tcp_writer_options_destroy(&d_twopt);
    d_twopt = nullptr;
  }
#endif
  if (d_fwopt != nullptr) {
    fstrm_writer_options_destroy(&d_fwopt);
    d_fwopt = nullptr;
  }
}

FrameStreamLogger::~FrameStreamLogger()
{
  this->cleanup();
}

void FrameStreamLogger::queueData(const std::string& data)
{
  if (!d_ioqueue || !d_iothr) {
    return;
  }
  uint8_t *frame = (uint8_t*)malloc(data.length());
  if (!frame) {
#ifdef RECURSOR
    g_log<<Logger::Warning<<"FrameStreamLogger: cannot allocate memory for stream."<<std::endl;
#else
    warnlog("FrameStreamLogger: cannot allocate memory for stream.");
#endif
    return;
  }
  memcpy(frame, data.c_str(), data.length());

  fstrm_res res;
  res = fstrm_iothr_submit(d_iothr, d_ioqueue, frame, data.length(), fstrm_free_wrapper, nullptr);

  if (res == fstrm_res_success) {
    // Frame successfully queued.
  } else if (res == fstrm_res_again) {
    free(frame);
#ifdef RECURSOR
    g_log<<Logger::Warning<<"FrameStreamLogger: queue full, dropping."<<std::endl;
#else
    warnlog("FrameStreamLogger: queue full, dropping.");
#endif
 } else {
    // Permanent failure.
    free(frame);
#ifdef RECURSOR
    g_log<<Logger::Warning<<"FrameStreamLogger: submitting to queue failed."<<std::endl;
#else
    warnlog("FrameStreamLogger: submitting to queue failed.");
#endif
  }
}

#endif /* HAVE_FSTRM */
