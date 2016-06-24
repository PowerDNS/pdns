% DNSPCAP2PROTOBUF(1)
% PowerDNS.com BV
% June 2016

# NAME
**dnspcap2protobuf** - A tool to convert PCAPs of DNS traffic to PowerDNS Protobuf

# SYNOPSIS
**dnspcap2protobuf** *PCAPFILE* *OUTFILE*

# DESCRIPTION
**dnspcap2protobuf** reads the PCAP file *PCAPFILE* for DNS queries and responses
and writes these in the PowerDNS protobuf format to *OUTFILE*.

# OPTIONS
--help
:    Show a summary of options.

--version
:    Display the version of dnspcap2protobuf
