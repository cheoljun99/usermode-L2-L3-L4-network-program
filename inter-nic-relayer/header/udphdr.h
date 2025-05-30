#pragma once

#include <cstdint>
#include <arpa/inet.h>

#pragma pack(push, 1)

struct UdpHdr final {
	uint16_t sport_;   // Source Port
	uint16_t dport_;   // Destination Port
	uint16_t len_;     // Length (UDP header + payload)
	uint16_t sum_;     // Checksum

	uint16_t sport() const { return ntohs(sport_); }
	uint16_t dport() const { return ntohs(dport_); }
	uint16_t len()   const { return ntohs(len_); }
	uint16_t sum()   const { return ntohs(sum_); }
};

typedef UdpHdr* PUdpHdr;

#pragma pack(pop)
