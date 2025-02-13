#include <unistd.h>
#include <sys/un.h>

#include "config.h"
#include "fstrm_logger.hh"

#ifdef RECURSOR
#include "logger.hh"
#include "logging.hh"
#else
#include "dolog.hh"
#endif

#ifdef HAVE_FSTRM

static const std::string DNSTAP_CONTENT_TYPE = "protobuf:dnstap.Dnstap";

FrameStreamLogger::FrameStreamLogger(const int family, std::string address, bool connect, const std::unordered_map<string, unsigned>& options) :
  d_family(family), d_address(std::move(address))
{
  try {
    d_fwopt = fstrm_writer_options_init();
    if (d_fwopt == nullptr) {
      throw std::runtime_error("FrameStreamLogger: fstrm_writer_options_init failed.");
    }

    auto res = fstrm_writer_options_add_content_type(d_fwopt, DNSTAP_CONTENT_TYPE.c_str(), DNSTAP_CONTENT_TYPE.size());
    if (res != fstrm_res_success) {
      throw std::runtime_error("FrameStreamLogger: fstrm_writer_options_add_content_type failed: " + std::to_string(res));
    }

    if (d_family == AF_UNIX) {
      struct sockaddr_un local{};
      if (makeUNsockaddr(d_address, &local) != 0) {
        throw std::runtime_error("FrameStreamLogger: Unable to use '" + d_address + "', it is not a valid UNIX socket path.");
      }

      d_uwopt = fstrm_unix_writer_options_init();
      if (d_uwopt == nullptr) {
        throw std::runtime_error("FrameStreamLogger: fstrm_unix_writer_options_init failed.");
      }

      // void return, no error checking.
      fstrm_unix_writer_options_set_socket_path(d_uwopt, d_address.c_str());

      d_writer = fstrm_unix_writer_init(d_uwopt, d_fwopt);
      if (d_writer == nullptr) {
        throw std::runtime_error("FrameStreamLogger: fstrm_unix_writer_init() failed.");
      }
#ifdef HAVE_FSTRM_TCP_WRITER_INIT
    }
    else if (family == AF_INET || family == AF_INET6) {
      d_twopt = fstrm_tcp_writer_options_init();
      if (d_twopt == nullptr) {
        throw std::runtime_error("FrameStreamLogger: fstrm_tcp_writer_options_init failed.");
      }

      try {
        ComboAddress inetAddress(d_address);

        // void return, no error checking.
        fstrm_tcp_writer_options_set_socket_address(d_twopt, inetAddress.toString().c_str());
        fstrm_tcp_writer_options_set_socket_port(d_twopt, std::to_string(inetAddress.getPort()).c_str());
      }
      catch (PDNSException& e) {
        throw std::runtime_error("FrameStreamLogger: Unable to use '" + d_address + "': " + e.reason);
      }

      d_writer = fstrm_tcp_writer_init(d_twopt, d_fwopt);
      if (d_writer == nullptr) {
        throw std::runtime_error("FrameStreamLogger: fstrm_tcp_writer_init() failed.");
      }
#endif
    }
    else {
      throw std::runtime_error("FrameStreamLogger: family " + std::to_string(family) + " not supported");
    }

    d_iothropt = fstrm_iothr_options_init();
    if (d_iothropt == nullptr) {
      throw std::runtime_error("FrameStreamLogger: fstrm_iothr_options_init() failed.");
    }

    res = fstrm_iothr_options_set_queue_model(d_iothropt, FSTRM_IOTHR_QUEUE_MODEL_MPSC);
    if (res != fstrm_res_success) {
      throw std::runtime_error("FrameStreamLogger: fstrm_iothr_options_set_queue_model failed: " + std::to_string(res));
    }

    struct setters
    {
      const std::string name;
      fstrm_res (*function)(struct fstrm_iothr_options*, const unsigned int);
    };
    const std::array<struct setters, 6> list = {{{"bufferHint", fstrm_iothr_options_set_buffer_hint},
                                                 {"flushTimeout", fstrm_iothr_options_set_flush_timeout},
                                                 {"inputQueueSize", fstrm_iothr_options_set_input_queue_size},
                                                 {"outputQueueSize", fstrm_iothr_options_set_output_queue_size},
                                                 {"queueNotifyThreshold", fstrm_iothr_options_set_queue_notify_threshold},
                                                 {"setReopenInterval", fstrm_iothr_options_set_reopen_interval}}};

    for (const auto& entry : list) {
      if (auto option = options.find(entry.name); option != options.end() && option->second != 0) {
        auto result = entry.function(d_iothropt, option->second);
        if (result != fstrm_res_success) {
          throw std::runtime_error("FrameStreamLogger: setting " + string(entry.name) + " failed: " + std::to_string(result));
        }
      }
    }

    if (connect) {
      d_iothr = fstrm_iothr_init(d_iothropt, &d_writer);
      if (d_iothr == nullptr) {
        throw std::runtime_error("FrameStreamLogger: fstrm_iothr_init() failed.");
      }

      d_ioqueue = fstrm_iothr_get_input_queue(d_iothr);
      if (d_ioqueue == nullptr) {
        throw std::runtime_error("FrameStreamLogger: fstrm_iothr_get_input_queue() failed.");
      }
    }
  }
  catch (std::runtime_error& e) {
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

RemoteLoggerInterface::Result FrameStreamLogger::queueData(const std::string& data)
{
  if ((d_ioqueue == nullptr) || d_iothr == nullptr) {
    ++d_permanentFailures;
    return Result::OtherError;
  }
  uint8_t* frame = (uint8_t*)malloc(data.length()); // NOLINT: it's the API
  if (frame == nullptr) {
    ++d_tooLargeCount;
    return Result::TooLarge;
  }
  memcpy(frame, data.c_str(), data.length());

  auto res = fstrm_iothr_submit(d_iothr, d_ioqueue, frame, data.length(), fstrm_free_wrapper, nullptr);

  if (res == fstrm_res_success) {
    // Frame successfully queued.
    ++d_framesSent;
    // do not call free here
    return Result::Queued;
  }
  if (res == fstrm_res_again) {
    free(frame); // NOLINT: it's the API
    ++d_queueFullDrops;
    return Result::PipeFull;
  }
  // Permanent failure.
  free(frame); // NOLINT: it's the API
  ++d_permanentFailures;
  return Result::OtherError;
}

#endif /* HAVE_FSTRM */
