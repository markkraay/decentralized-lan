#pragma once

#include <stdint.h>
#include <netinet/ip.h>

#include <string>

namespace network_utils {
	std::string get_source_address_from_ipv4(struct iphdr *h);
	void dump(const unsigned char *data_buffer, const unsigned int length);
	uint16_t icmp_checksum(uint16_t *icmph, int len);
};