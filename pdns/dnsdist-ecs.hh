#pragma once

int rewriteResponseWithoutEDNS(const char * packet, size_t len, vector<uint8_t>& newContent);
int locateEDNSOptRR(char * packet, size_t len, char ** optStart, size_t * optLen, bool * last);
void handleEDNSClientSubnet(char * packet, size_t packetSize, unsigned int consumed, uint16_t * len, string& largerPacket, bool* ednsAdded, bool* ecsAdded, const ComboAddress& remote);
void generateOptRR(const std::string& optRData, string& res);
int removeEDNSOptionFromOPT(char* optStart, size_t* optLen, const uint16_t optionCodeToRemove);
int rewriteResponseWithoutEDNSOption(const char * packet, const size_t len, const uint16_t optionCodeToSkip, vector<uint8_t>& newContent);
