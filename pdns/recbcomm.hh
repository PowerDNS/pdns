#ifndef PDNS_RECBCOMM
#define PDNS_RECBCOMM

#include <iostream>
#include <string>
#include "logger.hh"
#include "ahuexception.hh"
#include "dnspacket.hh"

using namespace std;

class SyncresCommunicator 
{
public:
  SyncresCommunicator();
  void giveQuestion(DNSPacket *p);
private:
  static void *threadHelper(void *self);
  void thread();
  pid_t d_pid;
  int d_fd;
  pthread_t d_tid;
};
#endif
