#pragma once

#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
	uint8_t vhl;       // version(4) + header length(4)
	uint8_t tos;       // type of service
	uint16_t len;      // total length
	uint16_t id;       // identification
	uint16_t off;      // fragment offset field
	uint8_t ttl;       // time to live
	uint8_t p;         // protocol
	uint16_t sum;      // checksum
	Ip sip_;           // source IP
	Ip dip_;           // destination IP

	Ip sip() { return Ip(ntohl(sip_)); }
	Ip dip() { return Ip(ntohl(dip_)); }

};
typedef IpHdr* PIpHdr;
#pragma pack(pop)
