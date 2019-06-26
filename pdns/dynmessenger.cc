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
#include "dynmessenger.hh"
#include <cstdio>
#include "utility.hh"
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>

DynMessenger::DynMessenger(const string &fname,
    int timeout_sec,
    int timeout_usec)
{
  d_s=socket(AF_UNIX,SOCK_STREAM,0);
  setCloseOnExec(d_s);
  
  if(d_s<0) {
    throw PDNSException(string("socket")+stringerror());
  }

  try {
    if(makeUNsockaddr(fname, &d_remote))
      throw PDNSException("Unable to connect to remote '"+fname+"': Path is not a valid UNIX socket path.");

    struct timeval timeout;
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = timeout_usec;

    if (setsockopt (d_s, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
      throw PDNSException("Unable to set SO_RCVTIMEO option on socket: " + stringerror());

    if (setsockopt (d_s, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
      throw PDNSException("Unable to set SO_SNDTIMEO option on socket: " + stringerror());

    int ret = Utility::timed_connect(d_s,(sockaddr*)&d_remote,sizeof(d_remote), timeout_sec, timeout_usec);

    if (ret == 0)
      throw TimeoutException("Unable to connect to remote '"+fname+"': "+stringerror());
    else if (ret < 0)
      throw PDNSException("Unable to connect to remote '"+fname+"': "+stringerror());

  } catch(...) {
    close(d_s);
    d_s=-1;
    throw;
  }
}

DynMessenger::DynMessenger(const ComboAddress& remote,
    const string &secret,
    int timeout_sec,
    int timeout_usec)
{
  d_s=socket(AF_INET, SOCK_STREAM,0);
  setCloseOnExec(d_s);
 
  if(d_s<0) {
    throw PDNSException(string("socket")+stringerror());
  }

  try {
    struct timeval timeout;
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = timeout_usec;

    if (setsockopt (d_s, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
      throw PDNSException("Unable to set SO_RCVTIMEO option on socket: " + stringerror());

    if (setsockopt (d_s, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
      throw PDNSException("Unable to set SO_SNDTIMEO option on socket: " + stringerror());

    int ret = Utility::timed_connect(d_s, (sockaddr*)&remote, remote.getSocklen(), timeout_sec, timeout_usec);

    if (ret == 0)
      throw TimeoutException("Unable to connect to remote '"+remote.toStringWithPort()+"': "+stringerror());
    else if (ret < 0)
      throw PDNSException("Unable to connect to remote '"+remote.toStringWithPort()+"': "+stringerror());

    string login=secret+"\n";
    writen2(d_s, login);
  } catch(...) {
    close(d_s);
    d_s=-1;
    throw;
  }
}

DynMessenger::~DynMessenger()
{
  if (d_s > 0)
    close(d_s);
}   

int DynMessenger::send(const string &msg) const
{
  try {
    writen2(d_s, msg+"\n");
    return 0;
  } catch(std::runtime_error& e) {
    if (errno == EAGAIN)
      throw TimeoutException("Error from remote in send(): " + string(e.what()));
    else
      throw PDNSException("Error from remote in send(): " + string(e.what()));
  }
}

string DynMessenger::receive() const 
{
  char buffer[1500];

  int retlen;
  string answer;
  for(;;) {
    retlen=recv(d_s,buffer,sizeof(buffer),0);
    if(retlen<0) {
      if (errno == EAGAIN)
        throw TimeoutException("Error from remote in receive(): " + stringerror());
      else
        throw PDNSException("Error from remote in receive(): " + stringerror());
    }

    answer.append(buffer,retlen);
    if (retlen == 0)
      break;
  }

  return answer;
}

