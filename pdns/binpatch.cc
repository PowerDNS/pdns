/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation
    

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include <iostream>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <errno.h>
#include <climits>
#include <string>
#include <map>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/types.h>

#include <sys/stat.h>


using namespace std;

static void imbue(char *pname, const char *search, const string &replace);
static string stringerror();
static off_t filesize(int fd);

int main(int argc, char **argv)
{
  if(argc!=3) {
    cerr<<"Syntax: binpatch binary configuration-directory"<<endl;
    exit(0);
  }

  imbue(argv[1],"!@@SYSCONFDIR@@:",argv[2]);
}

static void imbue(char *pname, const char *search, const string &replace)
{
  int fd=open(pname, O_RDWR);
  if(fd<0) {
    cerr<<"Unable to open executable read/write for imbuing: "<<stringerror()<<endl;
    exit(1);
  }
  int fs=filesize(fd);
  void *ptr=mmap(0,fs,PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if(ptr==(caddr_t)-1) {
    cerr<<"Unable to mmap executable read/write for imbuing: "<<stringerror()<<endl;
    exit(1);
  }
  
  char *p=(char *)ptr;
  char *end=p+fs;
  for(;p<end;++p) 
    if(*p==*search && *(p+1)==*(search+1) && !memcmp(p,search,strlen(search)))
      break;

  if(p==end) {
    cerr<<"Cannot find marker in binary, not imbueing"<<endl;
    exit(1);
  }
  strcpy(p+strlen(search),replace.c_str());
  munmap(ptr,filesize(fd));
  close(fd);
  cerr<<"Imbued configuration location '"<<replace<<"'"<<endl;
  return;
}

static off_t filesize(int fd)
{
  struct stat buf;
  fstat(fd, &buf);
  return buf.st_size;
}
static string stringerror()
{
  return strerror(errno);
}
