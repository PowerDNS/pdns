#include "signingpipe.hh"

bool ChunkedSigningPipe::submit(const DNSResourceRecord& rr)
{
  if(!d_toSign.empty() && (d_toSign.begin()->qtype.getCode() != rr.qtype.getCode()  ||  !pdns_iequals(d_toSign.begin()->qname, rr.qname))) 
  {
    flushToSign();
  }
  d_toSign.push_back(rr);
  return d_chunk.size() > d_chunkrecords;
}

void ChunkedSigningPipe::flushToSign()
{
  addRRSigs(d_dk, d_db, d_signer, d_toSign); // should start returning sigs separately instead of interleaved
  copy(d_toSign.begin(), d_toSign.end(), back_inserter(d_chunk));
  d_toSign.clear();
}

vector<DNSResourceRecord> ChunkedSigningPipe::getChunk(bool final)
{
  if(final)
    flushToSign();
  
  
  chunk_t::size_type amount=min(d_chunkrecords, d_chunk.size());
  chunk_t chunk;
  copy(d_chunk.begin(), d_chunk.begin() + amount, back_inserter(chunk));
      
  vector<DNSResourceRecord> overhang(d_chunk.begin() + amount, d_chunk.end());
  d_chunk.swap(overhang);
  
  return chunk;
}
