#include "misc.hh"
#include "logger.hh"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "dns_random.hh"

void seedRandom(const string& source)
{
  L<<Logger::Warning<<"Reading random entropy from '"<<source<<"'"<<endl;

  int fd=open(source.c_str(), O_RDONLY);
  if(fd < 0) {
    L<<Logger::Error<<"Unable to open source of random '"<<source<<"': "<<stringerror()<<endl;
    exit(EXIT_FAILURE);
  }
  char seed[16];
  int ret;
  int pos=0;
  while(pos!=sizeof(seed)) {
    ret = read(fd, seed+pos, sizeof(seed)-pos);
    if(ret < 0) {
      L<<Logger::Error<<"Unable to read random seed from "<<source<<": "<<stringerror()<<endl;
      close(fd);
      exit(EXIT_FAILURE);
    }
    if(!ret) {
      L<<Logger::Error<<"Unable to read random seed from "<<source<<": end of file"<<endl;
      close(fd);
      exit(EXIT_FAILURE);
    }
    pos+=ret;
  }
  close(fd);
  dns_random_init(seed);
}
