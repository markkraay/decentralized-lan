#include "find_hosts.hpp"

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>

#include <string>
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>

uint16_t checksum(uint16_t *icmph, int len) {
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

bool ping_broadcast() {
	struct sockaddr_in addr; // The address that we are pinging.
	const int on = 1;

	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;

	char *broadcast_ip = "192.168.1.255";
	if (inet_aton(broadcast_ip, &addr.sin_addr) == 0) {
		perror("inet_aton");
		printf("%s isn't a valid IP address.\n", broadcast_ip);
		return false;
	}

	int sock_fd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock_fd < 0) {
		perror("socket");
		return false;
	}

	if (setsockopt(sock_fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof on) != 0)
		perror("setsocketopt");

#ifdef __APPLE__
	struct icmp icmp_header;

#elif __linux
	struct icmphdr icmp_header;
	memset(&icmp_header, '0', sizeof icmp_header);
	icmp_header.type = ICMP_ECHO;
	icmp_header.code = 0;
	icmp_header.checksum = 0;
	icmp_header.checksum = checksum((u_int16_t *)&icmp_header, sizeof icmp_header);
#endif

	// Set a breakpoint and cross reference the raw bits
	if (sendto(sock_fd, &icmp_header, sizeof icmp_header, 0, (struct sockaddr *)&addr, sizeof addr) <= 0) {
		perror("sendto: ");
		return false;
	}
}

void dump(const unsigned char *data_buffer, const unsigned int length) {
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

void process_ether_header(struct ether_header *h) {
	u_char *ptr = h->ether_dhost;
	int i = ETHER_ADDR_LEN;
	printf("Destination Address: ");
	do {
		printf("%s%x", (i == ETHER_ADDR_LEN) ? " " : ":", *ptr++);
	} while (--i > 0);
	printf(" Source Address: ");
	ptr = h->ether_shost;
	i = ETHER_ADDR_LEN;
	printf("Source Address: ");
	do {
		printf("%s%x", (i == ETHER_ADDR_LEN) ? " " : ":", *ptr++);
	} while (--i > 0);
	printf("\n");
}

std::string get_source_address_from_ipv4(struct ip *h) {
	struct sockaddr_in ip;
	ip.sin_addr = h->ip_src;
	char *address = inet_ntoa(ip.sin_addr);
	return std::string(address);
}

std::vector<int> connect_to_nodes() {
	char error_buffer[PCAP_ERRBUF_SIZE];
	char *device = pcap_lookupdev(error_buffer);
	if (device == NULL) {
		fprintf(stderr, "pcap_lookupdev failed: %s", error_buffer);
		exit(EXIT_FAILURE);
	}

  bpf_u_int32 maskp; // Subnet mask
  bpf_u_int32 netp; // IP     
	pcap_lookupnet(device, &netp, &maskp, error_buffer); // Getting the IP address and subnet mask

	printf("Sniffing on device %s\n", device);
	pcap_t *pcap_handle = pcap_open_live(device, 4096, 1, 0, error_buffer);
	if (pcap_handle == NULL) {
		fprintf(stderr, "pcap_open_live failed: %s", error_buffer);
		exit(EXIT_FAILURE);
	} 

	// Creating a packet filter so that only ICMP packets will be read
	struct bpf_program fp;
	if (pcap_compile(pcap_handle, &fp, "icmp[0] == 0", 0, netp) == -1) { 
		fprintf(stderr, "pcap_compile failed.");
		exit(EXIT_FAILURE);
	}

	// Set the filter
	if (pcap_setfilter(pcap_handle, &fp) == -1) {
		fprintf(stderr, "pcap_setfilter failed.");
		exit(EXIT_FAILURE);
	}

	ping_broadcast();

  // Read the packets for one minute
	std::vector<int> node_fds;
	auto finish = std::chrono::system_clock::now() + std::chrono::seconds(100);
	do {
		pcap_pkthdr header;
		const u_char* packet = pcap_next(pcap_handle, &header);
		printf("%d", sizeof(struct ether_header));
		std::string address = get_source_address_from_ipv4((struct ip *)(packet + sizeof(struct ether_header)));
		std::cout << "Found address: " << address << ". Attempting to connect..." << std::endl;
		node_fds.push_back(connect_to_node(address, 3390));
	} while (std::chrono::system_clock::now() < finish);
	return node_fds;
}

int connect_to_node(std::string node_ip, int port) {
	struct sockaddr_in node_addr;
	int sock;
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "socket creation error");
		exit(EXIT_FAILURE);
	}

	memset(&node_addr, '0', sizeof(node_addr));
	node_addr.sin_family = AF_INET;
	node_addr.sin_port = htons(port);

	// Convert IPv4 and IPv6 addresses from text to binary
	if (inet_pton(AF_INET, node_ip.c_str(), &node_addr.sin_addr) <= 0) {
		return -1;
	}

	// Connect to the URL
	if (connect(sock, (struct sockaddr *)&node_addr, sizeof(node_addr)) < 0) {
		fprintf(stderr, "connection to %s failed\n", node_ip.c_str());
		return -1;
	}

	printf("connection to %s succeeded\n", node_ip.c_str());
	return sock;
}