#include "network_utils.hpp"

#include "nlohmann/json.hpp"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>

#include <regex>
#include <iostream>

std::string network_utils::get_source_address_from_ipv4(ip_header *h) {
	struct sockaddr_in ip;
#ifdef __APPLE__
	ip.sin_addr = h->ip_src;
#elif __linux
	ip.sin_addr.s_addr = h->saddr;
#endif
	char *address = inet_ntoa(ip.sin_addr);
	return std::string(address);
}

void network_utils::dump(const unsigned char *data_buffer, const unsigned int length) {
	unsigned char byte;
	unsigned int i, j;
	for (i=0; i < length; i++) {
		byte = data_buffer[i];
		printf("%02x ", data_buffer[i]); 
		if (((i % 16) == 15) || (i == length - 1)) {
			for (j=0; j < 15 - (i % 16); j++) 
				printf("  ");
			printf("| ");
			for (j=(i-(i % 16)); j <= i; j++) { 
				byte = data_buffer[j];
				if ((byte > 31) && (byte < 127)) 
					printf("%c", byte);
				else
					printf(".");
			}
			printf("\n"); 
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

std::string network_utils::resolve_fd(int fd) {
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	if (getpeername(fd, (struct sockaddr *)&addr, &len) == -1) {
		perror("resolve_fd: ");
		exit(EXIT_FAILURE);
	}
	return inet_ntoa(addr.sin_addr);
}

http::request network_utils::parse_http_request(const std::string& http_string) { 
	std::cout << http_string << std::endl;

	std::smatch matches;
	http::request request {
		http::request::method::GET,
		"/",
		""
	};

	// Checking if it is a "GET", "POST", "PUT", or "DELETE" request
	std::regex_search(http_string, matches, std::regex(R"~(\w+\ )~"));
	std::string request_method = matches[0].str();

	if (request_method == "GET ") {
		std::regex_search(http_string, matches, std::regex(R"~(GET ((\/\w*)+))~"));
		request.path = matches[1].str();
	} else if (request_method == "POST ") { 
		request.method = http::request::method::POST;

		std::regex_search(http_string, matches, std::regex(R"~(POST ((\/\w*)+))~"));
		request.path = matches[1].str();

		std::regex_search(http_string, matches, std::regex(R"~(\r\n\r\n([\w\ ]*))~"));
		request.payload = matches[1].str();
	} else {
		return {};
	}

	// If the data is given in json format, try and parse it.
	std::regex_search(http_string, matches, std::regex(R"~(Content-Type: application\/json)~"));
	if (matches.size() > 0) { // The match was made
		std::regex_search(http_string, matches, std::regex(R"~(\r\n\r\n(.*))~"));
		request.payload = nlohmann::json::parse(std::string(matches[1]));
	}

	return request;
}

std::string network_utils::get_ipv4_lan_address(const std::string& device) {
	struct ifaddrs *ifaddr, *ifa;
  int family, s;
  char host[NI_MAXHOST];

  if (getifaddrs(&ifaddr) == -1)
  {
      perror("getifaddrs");
      exit(EXIT_FAILURE);
  }

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
  {
    if (ifa->ifa_addr == NULL)
      continue;

		if (ifa->ifa_addr->sa_family == AF_INET) {
    	s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
    	if (s == 0 && strcmp(ifa->ifa_name, device.c_str()) == 0) {
				return std::string(host);
			}
		}
  }

	return "";
}