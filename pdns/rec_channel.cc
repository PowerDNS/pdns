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

#include "pdnsexception.hh"

#include "namespaces.hh"

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

RecursorControlChannel::Answer RecursorControlChannel::recv(int fd, unsigned int timeout)
{
  int ret = waitForData(fd, timeout, 0);
  if (ret == 0) {
    throw PDNSException("Timeout waiting for answer from control channel");
  }
  int err;
  if (::recv(fd, &err, sizeof(err), 0) != sizeof(err)) {
    throw PDNSException("Unable to receive return status over control channel: " + stringerror());
  }
  size_t len;
  if (::recv(fd, &len, sizeof(len), 0) != sizeof(len)) {
    throw PDNSException("Unable to receive length over control channel: " + stringerror());
  }

  string str;
  str.reserve(len);
  while (str.length() < len) {
    char buffer[1024];
    ssize_t recvd = ::recv(fd, buffer, sizeof(buffer), 0);
    if (recvd <= 0) {
      // EOF means we have a length error
      throw PDNSException("Unable to receive message over control channel: " + stringerror());
    }
    str.append(buffer, recvd);
  }

  return {err, str};
}
