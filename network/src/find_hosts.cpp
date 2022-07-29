#include "find_hosts.hpp"

#include <libnet.h>
#include <pcap.h>

#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <string>
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>

void ping_broadcast(char *broadcast_address) {
	printf("Attempting to send ping request to broadcast address.\n");

	// Default broadcast address
	if (broadcast_address == NULL) broadcast_address = "192.168.1.255"; 

	char error_buffer[LIBNET_ERRBUF_SIZE];
	libnet_t *libnet_ctx = libnet_init(LIBNET_RAW4, NULL, error_buffer);
	if (libnet_ctx == NULL) {
		fprintf(stderr, "libnet_init failed: %s", error_buffer);
		exit(EXIT_FAILURE);
	}

	// Generate a random ID
	libnet_seed_prand(libnet_ctx);
	u_int16_t id = (u_int16_t)libnet_get_prand(LIBNET_PR16);

	u_int32_t ip_addr = libnet_name2addr4(libnet_ctx, broadcast_address, LIBNET_DONT_RESOLVE);

	if (ip_addr == -1) {
		fprintf(stderr, "libnet_name2addr4 failed: %s", error_buffer);
		libnet_destroy(libnet_ctx);
		exit(EXIT_FAILURE);
	}

	// Building ICMP header
	u_int16_t seq = 1;
	if (libnet_build_icmpv4_echo(ICMP_ECHO, 0, 0, id, seq, NULL, 0, libnet_ctx, 0) == -1) {
		fprintf(stderr, "libnet_build_icmpv4_echo: %s", error_buffer);
		libnet_destroy(libnet_ctx);
		exit(EXIT_FAILURE);
	}

	// Building IP header
	if (libnet_autobuild_ipv4(LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H, IPPROTO_ICMP, ip_addr, libnet_ctx) == -1) {
		fprintf(stderr, "libnet_autobuild_ipv4_echo: %s", error_buffer);
		libnet_destroy(libnet_ctx);
		exit(EXIT_FAILURE);
	}

	// Writing packet
	int bytes_written = libnet_write(libnet_ctx);
	if (bytes_written != -1) {
		printf("%d bytes written.\n", bytes_written);
	} else {
		fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(libnet_ctx));
	}

	libnet_destroy(libnet_ctx);
	printf("Sucessfully sent ping request to broadcast address.\n");
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

void process_ether_header(struct ethhdr *h) {
	u_char *ptr = h->h_dest;
	int i = ETHER_ADDR_LEN;
	printf("Destination Address: ");
	do {
		printf("%s%x", (i == ETHER_ADDR_LEN) ? " " : ":", *ptr++);
	} while (--i > 0);
	printf(" Source Address: ");
	ptr = h->h_source;
	i = ETHER_ADDR_LEN;
	printf("Source Address: ");
	do {
		printf("%s%x", (i == ETHER_ADDR_LEN) ? " " : ":", *ptr++);
	} while (--i > 0);
	printf("\n");
}

std::string get_source_address_from_ipv4(struct iphdr *h) {
	struct sockaddr_in ip;
	ip.sin_addr.s_addr = h->saddr;
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

	ping_broadcast(NULL);

  // Read the packets for one minute
	std::vector<int> node_fds;
	auto finish = std::chrono::system_clock::now() + std::chrono::seconds(100);
	do {
		pcap_pkthdr header;
		const u_char* packet = pcap_next(pcap_handle, &header);
		std::string address = get_source_address_from_ipv4((struct iphdr *)(packet + sizeof(struct ethhdr)));
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