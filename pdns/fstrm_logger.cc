#include <unistd.h>
#include "fstrm_logger.hh"
#include "config.h"
#ifdef PDNS_CONFIG_ARGS
#include "logger.hh"
#define WE_ARE_RECURSOR
#else
#include "dolog.hh"
#endif
#include <sys/un.h>

#define DNSTAP_CONTENT_TYPE		"protobuf:dnstap.Dnstap"

FrameStreamLogger::FrameStreamLogger(const std::string socket_path): socket_path(socket_path)
{
  struct sockaddr_un local;
  local.sun_family = AF_UNIX;
  strcpy(local.sun_path, socket_path.c_str());

  fwopt = fstrm_writer_options_init();
  fstrm_res res = fstrm_writer_options_add_content_type(fwopt, DNSTAP_CONTENT_TYPE, sizeof(DNSTAP_CONTENT_TYPE) - 1);
  if (res != fstrm_res_success) {
#ifdef WE_ARE_RECURSOR
    L<<Logger::Warning<<"Error: fstrm_writer_options_add_content_type failed: "<<res<<std::endl;
#else
    warnlog("Error: fstrm_writer_options_add_content_type failed: %s\n", res);
#endif
  }

  uwopt = fstrm_unix_writer_options_init();
  fstrm_unix_writer_options_set_socket_path(uwopt, local.sun_path);

  writer = fstrm_unix_writer_init(uwopt, fwopt);
  if (!writer) {
#ifdef WE_ARE_RECURSOR
    L<<Logger::Warning<<"Error: fstrm_unix_writer_init() failed."<<std::endl;
#else
    warnlog("Error: fstrm_unix_writer_init(%s) failed.\n", socket_path);
#endif
  }

  iothr = fstrm_iothr_init(NULL, &writer);
  if (!iothr) {
#ifdef WE_ARE_RECURSOR
    L<<Logger::Warning<<"Error: fstrm_iothr_init() failed."<<std::endl;
#else
    warnlog("Error: fstrm_iothr_init() failed.\n");
#endif
  }

  ioqueue = fstrm_iothr_get_input_queue(iothr);
  if (!ioqueue) {
#ifdef WE_ARE_RECURSOR
    L<<Logger::Warning<<"Error: fstrm_iothr_get_input_queue() failed."<<std::endl;
#else
    warnlog("Error: fstrm_iothr_get_input_queue() failed.\n");
#endif
  }
}

FrameStreamLogger::~FrameStreamLogger()
{
  fstrm_unix_writer_options_destroy(&uwopt);
  fstrm_writer_options_destroy(&fwopt);
  fstrm_writer_destroy(&writer);
  fstrm_iothr_destroy(&iothr);
}

void FrameStreamLogger::queueData(const std::string& data)
{
  // Allocate a new frame from the template.
  uint8_t *frame = (uint8_t*)malloc(data.length());
  if (!frame) {
#ifdef WE_ARE_RECURSOR
      L<<Logger::Warning<<"Error: cannot allocate memory for frame stream"<<std::endl;
#else
      warnlog("Error: cannot allocate memory for frame stream");
#endif
    return;
  }
  memcpy(frame, data.c_str(), data.length());
  // Submit the frame for writing.
  for (;;) {
    fstrm_res res;
    res = fstrm_iothr_submit(iothr, ioqueue, frame,
                             data.length(),
                             fstrm_free_wrapper, NULL);

    if (res == fstrm_res_success) {
      // Frame successfully queued.
      break;
    } else if (res == fstrm_res_again) {
      // Queue is full.
#ifdef WE_ARE_RECURSOR
      L<<Logger::Warning<<"Frame stream queue full"<<std::endl;
#else
      warnlog("Frame stream queue full");
#endif
      continue;
    } else {
      // Permanent failure.

      free(frame);

#ifdef WE_ARE_RECURSOR
      L<<Logger::Warning<<"fstrm_iothr_submit() failed."<<std::endl<<stderr<<std::endl;
#else
      warnlog("fstrm_iothr_submit() failed.\n", stderr);
#endif
      break;
    }
  }
}
