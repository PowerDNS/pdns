#ifndef PDNS_DNS_RANDOM
#define PDNS_DNS_RANDOM

void dns_random_init(const char data[16]);
unsigned int dns_random(unsigned int n);

#endif
