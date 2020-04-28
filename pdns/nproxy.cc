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
#include <bitset>
#include "dnsparser.hh"
#include "iputils.hh"
#include <boost/program_options.hpp>

#include <boost/format.hpp>
#include <boost/utility.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/algorithm/string.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <grp.h>
#include <unistd.h>
#include "dnsrecords.hh"
#include "mplexer.hh"
#include "statbag.hh"

#include "namespaces.hh"
using namespace ::boost::multi_index;
#include "namespaces.hh"

namespace po = boost::program_options;
po::variables_map g_vm;

StatBag S;

FDMultiplexer* g_fdm;
int g_pdnssocket;
bool g_verbose;

struct NotificationInFlight
{
  ComboAddress source;
  time_t resentTime;
  DNSName domain;
  uint16_t origID, resentID;
  int origSocket;
};

typedef map<uint16_t, NotificationInFlight> nifs_t;
nifs_t g_nifs;

static void syslogFmt(const boost::format& fmt)
{
  cerr<<"nproxy: "<<fmt<<endl;
  syslog(LOG_WARNING, "%s", str(fmt).c_str());
}

static void handleOutsideUDPPacket(int fd, boost::any&)
try
{
  char buffer[1500];
  struct NotificationInFlight nif;
  /* make sure we report enough room for IPv6 */
  nif.source.sin4.sin_family = AF_INET6;
  nif.origSocket = fd;

  socklen_t socklen=nif.source.getSocklen();

  int res=recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&nif.source, &socklen);
  if(!res)
    return;

  if(res < 0) 
    throw runtime_error("reading packet from remote: "+stringerror());
    
  MOADNSParser mdp(true, string(buffer,res));
  nif.domain = mdp.d_qname;
  nif.origID = mdp.d_header.id;


  if(mdp.d_header.opcode == Opcode::Query && !mdp.d_header.qr && mdp.d_answers.empty() && mdp.d_qname.toString() == "pdns.nproxy." && 
     (mdp.d_qtype == QType::TXT || mdp.d_qtype ==QType::A)) {
    vector<uint8_t> packet;
    DNSPacketWriter pw(packet, mdp.d_qname, mdp.d_qtype);
    pw.getHeader()->id = mdp.d_header.id;
    pw.getHeader()->rd = mdp.d_header.rd;
    pw.getHeader()->qr = 1;

    pw.startRecord(mdp.d_qname, mdp.d_qtype);
    if(mdp.d_qtype == QType::TXT) {
      TXTRecordContent trc("\"OK\"");
      trc.toPacket(pw);
    }
    else if(mdp.d_qtype == QType::A) {
      ARecordContent arc("1.2.3.4");
      arc.toPacket(pw);
    }
    pw.commit();

    if(sendto(fd, &packet[0], packet.size(), 0, (struct sockaddr*)&nif.source, socklen) < 0) {
      syslogFmt(boost::format("Unable to send health check response to external nameserver %s - %s") % nif.source.toStringWithPort() % stringerror());
    }
    return;
  }

  if(mdp.d_header.opcode != Opcode::Notify || mdp.d_qtype != QType::SOA) {
    syslogFmt(boost::format("Received non-notification packet for domain '%s' from external nameserver %s") % nif.domain.toString() % nif.source.toStringWithPort());
    return;
  }
  syslogFmt(boost::format("External notification received for domain '%s' from %s") % nif.domain.toString() % nif.source.toStringWithPort());  
  vector<uint8_t> outpacket;
  DNSPacketWriter pw(outpacket, mdp.d_qname, mdp.d_qtype, 1, Opcode::Notify);

  static uint16_t s_idpool;
  pw.getHeader()->id = nif.resentID = s_idpool++;
  
  if(send(g_pdnssocket, &outpacket[0], outpacket.size(), 0) < 0) {
    throw runtime_error("Unable to send notify to PowerDNS: "+stringerror());
  }
  nif.resentTime=time(0);
  g_nifs[nif.resentID] = nif;

}
catch(std::exception &e)
{
  syslogFmt(boost::format("Error parsing packet from external nameserver: %s") % e.what());
}


static void handleInsideUDPPacket(int fd, boost::any&)
try
{
  char buffer[1500];
  struct NotificationInFlight nif;
  /* make sure we report enough room for IPv6 */
  nif.source.sin4.sin_family = AF_INET6;

  socklen_t socklen=nif.source.getSocklen();

  int len=recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&nif.source, &socklen);
  if(!len)
    return;

  if(len < 0) 
    throw runtime_error("reading packet from remote: "+stringerror());
    
  string packet(buffer, len);
  MOADNSParser mdp(false, packet);

  //  cerr<<"Inside notification response for: "<<mdp.d_qname<<endl;

  if(!g_nifs.count(mdp.d_header.id)) {
    syslogFmt(boost::format("Response from inner PowerDNS with unknown ID %1%") % (uint16_t)mdp.d_header.id);
    return;
  }
  
  nif=g_nifs[mdp.d_header.id];

  if(nif.domain != mdp.d_qname) {
    syslogFmt(boost::format("Response from inner nameserver for different domain '%s' than original notification '%s'") % mdp.d_qname.toString() % nif.domain.toString());
  } else {
    if(sendto(nif.origSocket, buffer, len, 0, (sockaddr*) &nif.source, nif.source.getSocklen()) < 0) {
      syslogFmt(boost::format("Unable to send notification response to external nameserver %s - %s") % nif.source.toStringWithPort() % stringerror());
    }
    else
      syslogFmt(boost::format("Sent notification response to external nameserver %s for domain '%s'") % nif.source.toStringWithPort() % nif.domain.toString());
  }
  g_nifs.erase(mdp.d_header.id);

}
catch(std::exception &e)
{
  syslogFmt(boost::format("Error parsing packet from internal nameserver: %s") % e.what());
}

static void expireOldNotifications()
{
  time_t limit = time(0) - 10;
  for(nifs_t::iterator iter = g_nifs.begin(); iter != g_nifs.end(); ) {
    if(iter->second.resentTime < limit) {
      syslogFmt(boost::format("Notification for domain '%s' was sent to inner nameserver, but no response within 10 seconds") % iter->second.domain.toString());
      g_nifs.erase(iter++);
    }
    else
      ++iter;
  }
}

static void daemonize(int null_fd)
{
  if(fork())
    exit(0); // bye bye

  setsid();

  dup2(null_fd,0); /* stdin */
  dup2(null_fd,1); /* stderr */
  dup2(null_fd,2); /* stderr */
}

static void usage(po::options_description &desc) {
  cerr<<"nproxy"<<endl;
  cerr<<desc<<endl;
}

int main(int argc, char** argv)
try
{
  reportAllTypes();
  openlog("nproxy", LOG_NDELAY | LOG_PID, LOG_DAEMON);

  g_fdm = FDMultiplexer::getMultiplexerSilent();
  if(!g_fdm) {
    throw std::runtime_error("Could not enable a multiplexer");
  }
  
  po::options_description desc("Allowed options");
  desc.add_options()
    ("help,h", "produce help message")
    ("version", "print the version")
    ("powerdns-address", po::value<string>(), "IP address of PowerDNS server")
    ("chroot", po::value<string>(), "chroot to this directory for additional security")
    ("setuid", po::value<int>(), "setuid to this numerical user id")
    ("setgid", po::value<int>(), "setgid to this numerical user id")
    ("origin-address", po::value<string>()->default_value("::"), "Source address for notifications to PowerDNS")
    ("listen-address", po::value<vector<string> >(), "IP addresses to listen on")
    ("listen-port", po::value<int>()->default_value(53), "Source port to listen on")
    ("daemon,d", po::value<bool>()->default_value(true), "operate in the background")
    ("verbose,v", "be verbose");

  po::store(po::command_line_parser(argc, argv).options(desc).run(), g_vm);
  po::notify(g_vm);

  if (g_vm.count("help")) {
    usage(desc);
    return EXIT_SUCCESS;
  }

  if (g_vm.count("version")) {
    cerr << "nproxy " << VERSION << endl;
    return EXIT_SUCCESS;
  }

  if(!g_vm.count("powerdns-address")) {
    cerr<<"Mandatory setting 'powerdns-address' unset:\n"<<endl;
    usage(desc);
    return EXIT_FAILURE;
  }

  if(!g_vm.count("verbose")) {
    g_verbose=true;
  }
  
  vector<string> addresses;
  if(g_vm.count("listen-address"))
    addresses=g_vm["listen-address"].as<vector<string> >();
  else
    addresses.push_back("::");

  // create sockets to listen on
  
  syslogFmt(boost::format("Starting up"));
  for(vector<string>::const_iterator address = addresses.begin(); address != addresses.end(); ++address) {
    ComboAddress local(*address, g_vm["listen-port"].as<int>());
    int sock = socket(local.sin4.sin_family, SOCK_DGRAM, 0);
    if(sock < 0)
      throw runtime_error("Creating socket for incoming packets: "+stringerror());

    if(::bind(sock,(sockaddr*) &local, local.getSocklen()) < 0)
      throw runtime_error("Binding socket for incoming packets to '"+ local.toStringWithPort()+"': "+stringerror());

    g_fdm->addReadFD(sock, handleOutsideUDPPacket); // add to fdmultiplexer for each socket
    syslogFmt(boost::format("Listening for external notifications on address %s") % local.toStringWithPort());
  }

  // create socket that talks to inner PowerDNS
  ComboAddress originAddress(g_vm["origin-address"].as<string>(), 0);
  g_pdnssocket=socket(originAddress.sin4.sin_family, SOCK_DGRAM, 0);
  if(g_pdnssocket < 0)
    throw runtime_error("Creating socket for packets to PowerDNS: "+stringerror());

  
  if(::bind(g_pdnssocket,(sockaddr*) &originAddress, originAddress.getSocklen()) < 0)
      throw runtime_error("Binding local address of inward socket to '"+ originAddress.toStringWithPort()+"': "+stringerror());
  

  ComboAddress pdns(g_vm["powerdns-address"].as<string>(), 53);
  if(connect(g_pdnssocket, (struct sockaddr*) &pdns, pdns.getSocklen()) < 0) 
    throw runtime_error("Failed to connect PowerDNS socket to address "+pdns.toStringWithPort()+": "+stringerror());

  syslogFmt(boost::format("Sending notifications from %s to internal address %s") % originAddress.toString() % pdns.toStringWithPort());

  g_fdm->addReadFD(g_pdnssocket, handleInsideUDPPacket);

  int null_fd=open("/dev/null",O_RDWR); /* open stdin */
  if(null_fd < 0)
    throw runtime_error("Unable to open /dev/null: "+stringerror());

  if(g_vm.count("chroot")) {
    if(chroot(g_vm["chroot"].as<string>().c_str()) < 0 || chdir("/") < 0)
      throw runtime_error("while chrooting to "+g_vm["chroot"].as<string>());
    syslogFmt(boost::format("Changed root to directory '%s'") % g_vm["chroot"].as<string>());
  }

  if(g_vm.count("setgid")) {
    if(setgid(g_vm["setgid"].as<int>()) < 0)
      throw runtime_error("while changing gid to "+std::to_string(g_vm["setgid"].as<int>()));
    syslogFmt(boost::format("Changed gid to %d") % g_vm["setgid"].as<int>());
    if(setgroups(0, NULL) < 0)
      throw runtime_error("while dropping supplementary groups");
  }

  if(g_vm.count("setuid")) {
    if(setuid(g_vm["setuid"].as<int>()) < 0)
      throw runtime_error("while changing uid to "+std::to_string(g_vm["setuid"].as<int>()));
    syslogFmt(boost::format("Changed uid to %d") % g_vm["setuid"].as<int>());
  }

  if(g_vm["daemon"].as<bool>()) {
    syslogFmt(boost::format("Daemonizing"));
    daemonize(null_fd);
  }
  close(null_fd);
  syslogFmt(boost::format("Program operational"));


  // start loop
  struct timeval now;
  for(;;) {
    gettimeofday(&now, 0);
    g_fdm->run(&now);
    // check for notifications that have been outstanding for more than 10 seconds
    expireOldNotifications();
  }
}
catch(boost::program_options::error& e) 
{
  syslogFmt(boost::format("Error parsing command line options: %s") % e.what());
}
catch(std::exception& e)
{
  syslogFmt(boost::format("Fatal: %s") % e.what());
}
catch(PDNSException& e)
{
  syslogFmt(boost::format("Fatal: %s") % e.reason);
}
