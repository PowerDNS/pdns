#ifndef PDNS_SECPOLL_AUTH_HH
#define PDNS_SECPOLL_AUTH_HH
#include <time.h>
#include "namespaces.hh"

void doSecPoll(bool first);
extern std::string g_security_message;

#endif
