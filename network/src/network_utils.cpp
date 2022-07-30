#include "network_utils.hpp"

#include <arpa/inet.h>

std::string network_utils::get_source_address_from_ipv4(struct iphdr *h) {
	struct sockaddr_in ip;
	ip.sin_addr.s_addr = h->saddr;
	char *address = inet_ntoa(ip.sin_addr);
	return std::string(address);
}

void network_utils::dump(const unsigned char *data_buffer, const unsigned int length) {
	unsigned char byte;
	unsigned int i, j;
	for (i=0; i < length; i++) {
		byte = data_buffer[i];
		printf("%02x ", data_buffer[i]); // Display byte in hex
		if (((i % 16) == 15) || (i == length - 1)) {
			for (j=0; j < 15 - (i % 16); j++) 
				printf("  ");
			printf("| ");
			for (j=(i-(i % 16)); j <= i; j++) { // Display printable bytes from the line
				byte = data_buffer[j];
				if ((byte > 31) && (byte < 127)) // Outside printable character range
					printf("%c", byte);
				else
					printf(".");
			}
			printf("\n"); // End of the dump line (each line is 16 bytes)
		}
	}
	return;
}

uint16_t network_utils::icmp_checksum(uint16_t *icmph, int len) {
	uint16_t ret = 0;
	uint32_t sum = 0;
	uint16_t odd_byte;
	
	while (len > 1) {
		sum += *icmph++;
		len -= 2;
	}
	
	if (len == 1) {
		*(uint8_t*)(&odd_byte) = * (uint8_t*)icmph;
		sum += odd_byte;
	}
	
	sum =  (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	ret =  ~sum;
	
	return ret; 
}
