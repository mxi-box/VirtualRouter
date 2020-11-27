#pragma once
#include <winsock2.h>

class IPV4_PACKET {
public:
	unsigned char version_headerLength;
	unsigned char TOS;
	unsigned short totalLength;
	unsigned short id;
	unsigned short fragmentFlags;
	unsigned char TTL;
	unsigned char protocol;
	unsigned short checksum;
	unsigned int src;
	unsigned int dest;
	unsigned char extra[];
	inline unsigned short headerLength() {
		return (version_headerLength & 0x0F) * 4;
	}
	inline unsigned short payloadLength() {
		return ntohs(totalLength) - headerLength();
	}
	inline unsigned char *payload() {
		return (unsigned char*)this + headerLength();
	}
	unsigned int getFakeHeaderSum();
	void computeChecksum();
};

class UDP_PACKET {
public:
	unsigned short srcPort;
	unsigned short destPort;
	unsigned short length;
	unsigned short checksum;
	unsigned char payload[];

	inline unsigned int payloadLength() const{
		return ntohs(length) - 8;
	}
	void computeChecksum(unsigned int fakeHeaderSum);
};

class TCP_PACKET {
public:
	unsigned short srcPort;
	unsigned short destPort;
	unsigned long seq;
	unsigned long ack;
	unsigned short set;
	unsigned short windows;
	unsigned short checksum;
	unsigned short urgentPtr;
	unsigned char payload[];

	inline unsigned int payloadLength(const unsigned int &packetLength) const {
		return packetLength - (set >> 12) * 4;
	}
	void computeChecksum(const unsigned int& fakeHeaderSum, const unsigned int& packetLength);
};
inline bool isIPv4(unsigned char *data) {
	return (data[0] >> 4) == IPPROTO_IPV4;
}
