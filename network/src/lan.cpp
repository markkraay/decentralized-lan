#include "lan.hpp"

#include "network_utils.hpp"

#include <pcap.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <string>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <map>
#include <vector>

using namespace std::chrono;

/* Sends an ICMP Echo the LAN broadcast address
As a result, available devices on the network 
will send ICMP response packet's to the host machine,
acknowledging that they are on the network.
*/
bool lan::ping_broadcast() {
	struct sockaddr_in addr; // The address that we are pinging.
	const int on = 1;

	// Zero out the memory
	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;

	// Read the broadcast address into it's proper location in the socket address
	if (inet_aton(BROADCAST_ADDRESS, &addr.sin_addr) == 0) {
		perror("broadcast address: ");
		return false;
	}

	// Create a raw socket to send the ICMP request
	int sock_fd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock_fd < 0) {
		perror("ICMP request socket: ");
		return false;
	}

	// This socket option must be set so that we can ping the broadcast adddress
	if (setsockopt(sock_fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof on) != 0) {
		perror("setsocketopt SO_BROADCAST: ");
		return false;
	}

#ifdef __APPLE__
#elif __linux
	struct icmphdr icmp_header;
	memset(&icmp_header, '0', sizeof icmp_header);
	icmp_header.type = ICMP_ECHO;
	icmp_header.code = 0;
	icmp_header.checksum = 0;
	icmp_header.checksum = network_utils::icmp_checksum((u_int16_t *)&icmp_header, sizeof icmp_header);
#endif

	if (sendto(sock_fd, &icmp_header, sizeof icmp_header, 0, (struct sockaddr *)&addr, sizeof addr) <= 0) {
		perror("sendto: ");
		return false;
	}

	close(sock_fd);
	return true;
}

/* Tries to connect to nodes on the LAN.
First, establishing a libpcap device to sniff packets on. This
sniffs strictly ICMP packets from the network traffic. Then
repeatedly ping the broadcast address, for 100 seconds, while 
simulataneously reading packets from the network. Each packet
is assumed to be an ICMP response to the ping's request, so we 
decode the ICMP packet to yield the source IP of the packet and 
attempt a connection on the address.
*/
std::vector<int> lan::connect_to_nodes() {
	char error_buffer[PCAP_ERRBUF_SIZE];

	// Get the default ethernet device
	char *device = pcap_lookupdev(error_buffer);
	if (device == NULL) {
		std::cerr << "pcap_lookupdev: " << error_buffer << std::endl;
		exit(EXIT_FAILURE);
	}

  bpf_u_int32 maskp; // Subnet mask
  bpf_u_int32 netp; // IP     
	pcap_lookupnet(device, &netp, &maskp, error_buffer); // Getting the IP address and subnet mask

	std::cout << "Sniffing on device " << device << std::endl;
	// Device, snaplen, promisc, timeout
	// pcap_t *pcap_handle = pcap_open_live(device, 4096, 1, 100, error_buffer);
	pcap_t *pcap_handle = pcap_create(device, error_buffer);
	if (pcap_handle == NULL) {
		std::cerr << "pcap creation failed: " << error_buffer << std::endl;
		exit(EXIT_FAILURE);
	}
	pcap_set_snaplen(pcap_handle, 4096);
	pcap_set_promisc(pcap_handle, 1);
	pcap_set_timeout(pcap_handle, 1000);
	pcap_set_immediate_mode(pcap_handle, 1);
	pcap_setnonblock(pcap_handle, 1, error_buffer);
	pcap_activate(pcap_handle);

	// Creating a packet filter so that only ICMP packets will be read
	struct bpf_program fp;
	if (pcap_compile(pcap_handle, &fp, "icmp[0] == 0", 0, netp) == -1) { 
		std::cerr << "Compiling BPF failed." << std::endl;
		exit(EXIT_FAILURE);
	}

	// Set the filter
	if (pcap_setfilter(pcap_handle, &fp) == -1) {
		std::cerr << "Setting PBF failed." << std::endl;
		exit(EXIT_FAILURE);
	}

	std::cout << "Attempting to connect to nodes on the LAN" << std::endl;
	std::map<std::string, int> address_fd;
	auto start = system_clock::now();
	auto next_broadcast = start;
	do {
		time_t now = system_clock::to_time_t(system_clock::now());
		if (system_clock::now() > next_broadcast) {
			bool ping_success = ping_broadcast();
			std::cout << std::put_time(std::localtime(&now), "%F %T") << " Pinging Broadcast: " << (ping_success ? "Success" : "Failed") << std::endl;
			next_broadcast = system_clock::now() + seconds(5);
		} else {
			pcap_pkthdr header;
			const u_char* packet = pcap_next(pcap_handle, &header);
			// Get the IP address from the packet
			if (packet != NULL) {
				std::string address = network_utils::get_source_address_from_ipv4((struct iphdr *)(packet + sizeof(struct ether_header)));
				if (address_fd.find(address) == address_fd.end()) { 
					std::cout << "Found address: " << address << ". Attempting to connect... " << std::endl;
					// Try to connect to the IP
					int conn_fd = connect_to_node(address);
					if (conn_fd == -1) {
						std::cerr << "\tConnection to " << address << " failed." << std::endl;
					}
					else {
						std::cout << "\tConnection to " << address << " succeeded. Added to known hosts on network." << std::endl;
						address_fd.insert(std::make_pair(address, conn_fd));
					}
				}
			}
		}
	} while (system_clock::now() < start + seconds(100));

	std::cout << "Finished" << std::endl;

	std::vector<int> fds;
	for (auto pair : address_fd) fds.push_back(pair.second);
	return fds;
}

int lan::connect_to_node(const std::string& node_ip) {
	struct sockaddr_in node_addr;
	int sock;

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		std::cerr << "socket creation error" << std::endl;
		return -1;
	}

	struct timeval timeout;
	timeout.tv_sec = 20; // Timeout length in seconds
	timeout.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

	memset(&node_addr, '0', sizeof(node_addr));
	node_addr.sin_family = AF_INET;
	node_addr.sin_port = htons(PORT);

	if (inet_pton(AF_INET, node_ip.c_str(), &node_addr.sin_addr) <= 0) {
		perror("inet_pton: ");
		return -1;
	}

	if (connect(sock, (struct sockaddr *)&node_addr, sizeof(node_addr)) == -1) {
		perror("connect: ");
		return -1;
	}

	return sock;
}