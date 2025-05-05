#pragma once

#include <cstdint>
#include <arpa/inet.h>

#pragma pack(push, 1)

struct TcpHdr final {
	uint16_t sport_;     // Source port
	uint16_t dport_;     // Destination port
	uint32_t seq_;       // Sequence number
	uint32_t ack_;       // Acknowledgment number
	uint8_t off_rsvd;    // Data offset (4 bits) + Reserved (4 bits)
	uint8_t flags;       // Flags (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
	uint16_t win;        // Window size
	uint16_t sum;        // Checksum
	uint16_t urp;        // Urgent pointer
	// options follow if data offset > 5 (not handled here)

	uint16_t sport() const { return ntohs(sport_); }
	uint16_t dport() const { return ntohs(dport_); }
	uint32_t seq() const { return ntohl(seq_); }
	uint32_t ack() const { return ntohl(ack_); }
	uint8_t dataOffset() const { return (off_rsvd >> 4); }
};

typedef TcpHdr* PTcpHdr;

#pragma pack(pop)
