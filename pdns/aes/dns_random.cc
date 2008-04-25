#include "aescpp.h"
#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include "dns_random.hh"

using namespace std;

static aes_encrypt_ctx g_cx;
static unsigned char g_counter[16];
static uint32_t g_in;

void dns_random_init(const char data[16])
{
  aes_init();

  aes_encrypt_key128((const unsigned char*)data, &g_cx);
  struct timeval now;
  gettimeofday(&now, 0);

  memcpy(g_counter, &now.tv_usec, sizeof(now.tv_usec));
  memcpy(g_counter+sizeof(now.tv_usec), &now.tv_sec, sizeof(now.tv_sec));
  g_in = getpid() | (getppid()<<16);
  srandom(dns_random(numeric_limits<uint32_t>::max()));
}

static void counterIncrement(unsigned char* counter)
{
  if(!++counter[0])
    if(!++counter[1])
      if(!++counter[2])
	if(!++counter[3])
	  if(!++counter[4])
	    if(!++counter[5])
	      if(!++counter[6])
		if(!++counter[7])
		  if(!++counter[8])
		    if(!++counter[9])
		      if(!++counter[10])
			if(!++counter[11])
			  if(!++counter[12])
			    if(!++counter[13])
			      if(!++counter[14])
				++counter[15];
  
}

unsigned int dns_random(unsigned int n)
{
  uint32_t out;
  aes_ctr_encrypt((unsigned char*) &g_in, (unsigned char*)& out, sizeof(g_in), g_counter, counterIncrement, &g_cx);
  return out % n;
}

#if 0
int main()
{
  dns_random_init("0123456789abcdef");

  for(int n = 0; n < 16; n++)
    cerr<<dns_random(16384)<<endl;
}
#endif
