#pragma once

#include "http/request.hpp"

#include <stdint.h>
#include <netinet/ip.h>

#include <string>

#ifdef __APPLE__
typedef struct ip ip_header;
#elif __linux
typedef struct iphdr ip_header;
#endif

namespace network_utils {
	std::string get_source_address_from_ipv4(ip_header *h);
	void dump(const unsigned char *data_buffer, const unsigned int length);
	uint16_t icmp_checksum(uint16_t *icmph, int len);
	std::string resolve_fd(int fd);
	http::request parse_http_request(const std::string& http_string);
	std::string get_ipv4_lan_address(const std::string& device);
};
