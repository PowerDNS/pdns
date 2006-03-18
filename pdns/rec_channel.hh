#ifndef PDNS_REC_CHANNEL
#define PDNS_REC_CHANNEL
#include <string>
#include <stdint.h>

/** this class is used both to send and answer channel commands to the PowerDNS Recursor */
class RecursorControlChannel
{
public:
  int listen(const std::string& filename);
  void connect(const std::string& filename);

  uint64_t getStat(const std::string& name);
private:
  int d_fd;
};

#endif 
