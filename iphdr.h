#pragma once

#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)

// IPv4 헤더 구조체
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

// IPv6 주소 타입 (128bit)
struct Ipv6Addr {
	uint8_t addr[16];
};

// IPv6 헤더 구조체
struct Ipv6Hdr final {
	uint32_t ver_tc_fl;   // version(4), traffic class(8), flow label(20)
	uint16_t payload_len; // payload length
	uint8_t next_header;  // next header (protocol)
	uint8_t hop_limit;    // hop limit (like TTL)
	Ipv6Addr sip;         // source IPv6 address
	Ipv6Addr dip;         // destination IPv6 address
};
typedef Ipv6Hdr* PIpv6Hdr;

#pragma pack(pop)