#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "rec_channel.hh"
#include "utility.hh"
#include <sys/socket.h>
#include <cerrno>
#include "misc.hh"
#include <string.h>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <iostream>
#include <limits.h>

#include "pdnsexception.hh"

#include "namespaces.hh"

/* g++ defines __SANITIZE_THREAD__
   clang++ supports the nice __has_feature(thread_sanitizer),
   let's merge them */
#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define __SANITIZE_THREAD__ 1
#endif
#if __has_feature(address_sanitizer)
#define __SANITIZE_ADDRESS__ 1
#endif
#endif

std::atomic<bool> RecursorControlChannel::stop = false;

RecursorControlChannel::RecursorControlChannel()
{
  d_fd = -1;
  *d_local.sun_path = 0;
  d_local.sun_family = 0;
}

RecursorControlChannel::~RecursorControlChannel()
{
  if (d_fd > 0)
    close(d_fd);
  if (*d_local.sun_path)
    unlink(d_local.sun_path);
}

int RecursorControlChannel::listen(const string& fname)
{
  d_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  setCloseOnExec(d_fd);

  if (d_fd < 0)
    throw PDNSException("Creating UNIX domain socket: " + stringerror());

  int tmp = 1;
  if (setsockopt(d_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&tmp, sizeof tmp) < 0)
    throw PDNSException("Setsockopt failed: " + stringerror());

  int err = unlink(fname.c_str());
  if (err < 0 && errno != ENOENT)
    throw PDNSException("Can't remove (previous) controlsocket '" + fname + "': " + stringerror() + " (try --socket-dir)");

  if (makeUNsockaddr(fname, &d_local))
    throw PDNSException("Unable to bind to controlsocket, path '" + fname + "' is not a valid UNIX socket path.");

  if (bind(d_fd, (sockaddr*)&d_local, sizeof(d_local)) < 0)
    throw PDNSException("Unable to bind to controlsocket '" + fname + "': " + stringerror());
  if (::listen(d_fd, 0) == -1) {
    throw PDNSException("Unable to listen on controlsocket '" + fname + "': " + stringerror());
  }
  return d_fd;
}

void RecursorControlChannel::connect(const string& path, const string& fname)
{
  struct sockaddr_un remote;

  d_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  setCloseOnExec(d_fd);

  if (d_fd < 0)
    throw PDNSException("Creating UNIX domain socket: " + stringerror());

  try {
    int tmp = 1;
    if (setsockopt(d_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&tmp, sizeof tmp) < 0)
      throw PDNSException("Setsockopt failed: " + stringerror());

    string remotename = path + "/" + fname;
    if (makeUNsockaddr(remotename, &remote))
      throw PDNSException("Unable to connect to controlsocket, path '" + remotename + "' is not a valid UNIX socket path.");

    if (::connect(d_fd, (sockaddr*)&remote, sizeof(remote)) < 0) {
      if (*d_local.sun_path)
        unlink(d_local.sun_path);
      throw PDNSException("Unable to connect to remote '" + string(remote.sun_path) + "': " + stringerror());
    }
  }
  catch (...) {
    close(d_fd);
    d_fd = -1;
    d_local.sun_path[0] = 0;
    throw;
  }
}

static void sendfd(int s, int fd)
{
  struct msghdr msg;
  struct cmsghdr* cmsg;
  union
  {
    struct cmsghdr hdr;
    unsigned char buf[CMSG_SPACE(sizeof(int))];
  } cmsgbuf;
  struct iovec io_vector[1];
  char ch = 'X';

  io_vector[0].iov_base = &ch;
  io_vector[0].iov_len = 1;

  memset(&msg, 0, sizeof(msg));
  msg.msg_control = &cmsgbuf.buf;
  msg.msg_controllen = sizeof(cmsgbuf.buf);
  msg.msg_iov = io_vector;
  msg.msg_iovlen = 1;

  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  *(int*)CMSG_DATA(cmsg) = fd;

  if (sendmsg(s, &msg, 0) == -1) {
    throw PDNSException("Unable to send fd message over control channel: " + stringerror());
  }
}

void RecursorControlChannel::send(int fd, const Answer& msg, unsigned int timeout, int fd_to_pass)
{
  int ret = waitForRWData(fd, false, timeout, 0);
  if (ret == 0) {
    throw PDNSException("Timeout sending message over control channel");
  }
  else if (ret < 0) {
    throw PDNSException("Error sending message over control channel:" + stringerror());
  }

  if (::send(fd, &msg.d_ret, sizeof(msg.d_ret), 0) < 0) {
    throw PDNSException("Unable to send return code over control channel: " + stringerror());
  }
  size_t len = msg.d_str.length();
  if (::send(fd, &len, sizeof(len), 0) < 0) {
    throw PDNSException("Unable to send length over control channel: " + stringerror());
  }
  if (::send(fd, msg.d_str.c_str(), len, 0) != static_cast<ssize_t>(len)) {
    throw PDNSException("Unable to send message over control channel: " + stringerror());
  }

  if (fd_to_pass != -1) {
    sendfd(fd, fd_to_pass);
  }
}

static void waitForRead(int fd, unsigned int timeout, time_t start)
{
  time_t elapsed = time(nullptr) - start;
  if (elapsed >= timeout) {
    throw PDNSException("Timeout waiting for control channel data");
  }
  // coverity[store_truncates_time_t]
  int ret = waitForData(fd, timeout - elapsed, 0);
  if (ret == 0) {
    throw PDNSException("Timeout waiting for control channel data");
  }
}

static size_t getArgMax()
{
#if defined(ARG_MAX)
  return ARG_MAX;
#endif

#if defined(_SC_ARG_MAX)
  auto tmp = sysconf(_SC_ARG_MAX);
  if (tmp != -1) {
    return tmp;
  }
#endif
  /* _POSIX_ARG_MAX */
  return 4096;
}

RecursorControlChannel::Answer RecursorControlChannel::recv(int fd, unsigned int timeout)
{
  // timeout covers the operation of all read ops combined
  const time_t start = time(nullptr);

  waitForRead(fd, timeout, start);
  int err{};
  auto ret = ::recv(fd, &err, sizeof(err), 0);
  if (ret == 0) {
#if defined(__SANITIZE_THREAD__)
    return {0, "bye nicely\n"}; // Hack because TSAN enabled build justs _exits on quit-nicely
#endif
    throw PDNSException("Unable to receive status over control connection: EOF");
  }
  if (ret != sizeof(err)) {
    throw PDNSException("Unable to receive return status over control channel: " + stringerror());
  }

  waitForRead(fd, timeout, start);
  size_t len;
  if (::recv(fd, &len, sizeof(len), 0) != sizeof(len)) {
    throw PDNSException("Unable to receive length over control channel: " + stringerror());
  }

  if (len > getArgMax()) {
    throw PDNSException("Length of control channel message too large");
  }

  string str;
  str.reserve(len);
  while (str.length() < len) {
    char buffer[1024];
    waitForRead(fd, timeout, start);
    size_t toRead = std::min(len - str.length(), sizeof(buffer));
    ssize_t recvd = ::recv(fd, buffer, toRead, 0);
    if (recvd <= 0) {
      // EOF means we have a length error
      throw PDNSException("Unable to receive message over control channel: " + stringerror());
    }
    str.append(buffer, recvd);
  }

  return {err, std::move(str)};
}
