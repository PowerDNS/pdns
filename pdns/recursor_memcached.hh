#ifndef PDNS_RECURSOR_MEMCACHED_HH
#define PDNS_RECURSOR_MEMCACHED_HH
#include <string>


class MemcachedCommunicator
{
public:
  MemcachedCommunicator(const std::string& servers);
  string get(const std::string& key);
  void set(const std::string& key, const std::string& value);
  struct UDPHeader
  {
    UDPHeader()
    {
      memset(this, 0, sizeof(*this));
    }
    uint16_t id;
    uint16_t seqNo;
    uint16_t totalDgrams;
    uint16_t mbZero;
  };

private:
  int d_socket;
};
#endif
