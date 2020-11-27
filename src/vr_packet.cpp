#include "stdafx.h"
#include "vr_packet.h"

unsigned int IPV4_PACKET::getFakeHeaderSum() {
	unsigned int sum = 0;
	sum += (src & 0xffff) + (src >> 16);
	sum += (dest & 0xffff) + (dest >> 16);
	sum += (int)protocol << 8;
	sum += htons(payloadLength());
	return sum;
}
void IPV4_PACKET::computeChecksum() {
	unsigned short* ptr = (unsigned short*)this;
	unsigned int sum = 0;
	checksum = 0;
	for (int i = 0; i < headerLength() / 2; i++) {
		sum += *(ptr + i);
	}
	sum = (sum & 0xffff) + (sum >> 16);
	checksum = ~((sum & 0xffff) + (sum >> 16));
}

void UDP_PACKET::computeChecksum(unsigned int fakeHeaderSum) {
	unsigned short* ptr = (unsigned short*)this;
	unsigned int sum = fakeHeaderSum;
	checksum = 0;
	int i = 0;
	for (; i < ntohs(length) / 2; i++) {
		sum += *(ptr + i);
	}
	if (i * 2 < ntohs(length)) {
		sum += *(unsigned char*)(ptr + i);
	}
	sum = (sum & 0xffff) + (sum >> 16);
	checksum = ~((sum & 0xffff) + (sum >> 16));
}

void TCP_PACKET::computeChecksum(const unsigned int& fakeHeaderSum, const unsigned int& packetLength) {
	unsigned short* ptr = (unsigned short*)this;
	unsigned int sum = fakeHeaderSum;
	checksum = 0;
	size_t i = 0;
	for (; i < packetLength / 2; i++) {
		sum += *(ptr + i);
	}
	if (i * 2 < packetLength) {
		sum += *(unsigned char*)(ptr + i);
	}
	sum = (sum & 0xffff) + (sum >> 16);
	checksum = ~((sum & 0xffff) + (sum >> 16));
}