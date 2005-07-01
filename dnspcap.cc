#include "dnspcap.hh"


PcapPacketReader::PcapPacketReader(const string& fname) : d_fname(fname)
{
  d_fp=fopen(fname.c_str(),"r");
  if(!d_fp)
    unixDie("Unable to open file");
  
  
  checkedFread(&d_pfh);
  
  if(d_pfh.magic != 2712847316UL)
    throw runtime_error((format("PCAP file %s has bad magic %x, should be %x") % fname % d_pfh.magic % 2712847316UL).str());
  
  if( d_pfh.linktype!=1)
    throw runtime_error((format("Unsupported link type %d") % d_pfh.linktype).str());
  
  d_runts = d_oversized = d_packets = 0;
}

~PcapPacketReader::PcapPacketReader()
{
  fclose(d_fp);
}


void PcapPacketReader::checkedFreadSize(void* ptr, size_t size) 
{
  int ret=fread(ptr, 1, size, d_fp);
  if(ret < 0)
    unixDie( (format("Error reading %d bytes from %s") % size % d_fname).str());
  
  if(!ret)
    throw EofException();
  
  if((size_t)ret != size)
    throw EofException((format("Incomplete read from '%s', got only %d bytes") % d_fname % ret).str());
}

bool PcapPacketReader::getUDPPacket()
try
{
  for(;;) {
    checkedFread(&d_pheader);

    if(d_pheader.caplen!=d_pheader.len) {
      d_runts++;
      if(fseek(d_fp, d_pheader.caplen, SEEK_SET)<0)
	unixDie((format("Skipping %d bytes in file %s") % d_pheader.caplen % d_fname).str());
      continue;
    }
    if(d_pheader.caplen > sizeof(d_buffer)) {
      d_oversized++;
      if(fseek(d_fp, d_pheader.caplen, SEEK_SET)<0)
	unixDie((format("Skipping %d bytes in file %s") % d_pheader.caplen % d_fname).str());
      continue;
    }
    
    checkedFreadSize(d_buffer, d_pheader.caplen);
    d_ip=reinterpret_cast<struct iphdr*>(d_buffer + sizeof(struct ether_header));
    
    if(d_ip->protocol==17) { // udp
      d_udp=reinterpret_cast<const struct udphdr*>(d_buffer + sizeof(struct ether_header) + 4 * d_ip->ihl);
      d_payload = (unsigned char*)d_udp + sizeof(struct udphdr);
      d_len = ntohs(d_udp->len) - sizeof(struct udphdr);
      d_packets++;
      return true;
    }
    else
      cerr<<"proto: "<<(int)d_ip->protocol<<endl;
  }
}
catch(EofException) {
  return false;
}


PcapPacketWriter::PcapPacketWriter(const string& fname, PcapPacketReader& ppr) : d_fname(fname), d_ppr(ppr)
{
  d_fp=fopen(fname.c_str(),"w");
  if(!d_fp)
    unixDie("Unable to open file");
  
  fwrite(&ppr.d_pfh, 1, sizeof(ppr.d_pfh), d_fp);
  
}

void PcapPacketWriter::write()
{
  fwrite(&d_ppr.d_pheader, 1, sizeof(d_ppr.d_pheader), d_fp);
  fwrite(d_ppr.d_buffer, 1, d_ppr.d_pheader.caplen, d_fp);
}

~PcapPacketWriter::PcapPacketWriter()
{
  fclose(d_fp);
}
