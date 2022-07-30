#include "node.hpp"

#include "lan.hpp"
#include "network_utils.hpp"

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <iostream>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

// Upon instantiation of a node, the "serve" function
// is called in a new thread, so that the node can 
Node::Node() {}

/* When this function is called, the node 
joins the network, making itself available to other
nodes so that they to can connect to the node.
*/
void Node::start() {
	// Creating TCP socket for communication with other nodes
	if ((this->node_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
		perror("Creation of server socket failed: ");
		exit(EXIT_FAILURE);
	}

	// Allow socket descriptors to be reusable
	int on = 1;
	if (setsockopt(this->node_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0) {
		perror("setsockopt SO_REUSEADDR failed: ");
		close(this->node_fd);
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in node_address;
	node_address.sin_family = AF_INET;
	node_address.sin_addr.s_addr = htonl(INADDR_ANY); // Use the default LAN IPv4 address
	node_address.sin_port = htons(PORT);
	memset(node_address.sin_zero, '\0', sizeof(node_address.sin_zero));

	if (bind(this->node_fd, (struct sockaddr *)&node_address, sizeof(node_address)) < 0) {
		perror("binding socket failed: ");
		close(this->node_fd);
		exit(EXIT_FAILURE);
	}

	if (listen(this->node_fd, 10) < 0) {
		perror("listen failed: ");
		close(this->node_fd);
		exit(EXIT_FAILURE);
	}

	// Zero out the memory so that no wrong revents are read.
	memset(pollfds, '\0', sizeof(pollfds));

	// Adding the node itself to the list of pollable file descriptors
	pollfds[0].fd = this->node_fd;
	pollfds[0].events = POLLIN | POLLPRI;

	//  Try to connect to other node's on the network
	int clients = 1; // The current number of clients (one because the server node)
	std::set<int> nodes = lan::connect_to_nodes();
	for (int node : nodes) {
		pollfds[clients].fd = node;
		pollfds[clients].events = POLLIN | POLLPRI;
		clients++;
	}

	char buffer[SOCKET_BUFFER_SIZE]; // For reading messages from the nodes
	while (true) {
		// currentClient + 1 to include the node itself in the size
		int pollResult = poll(pollfds, clients, 5000); 
		if (pollResult > 0) { // Some events have been detected
			// Processing events for the server node.
			if (pollfds[0].revents & POLLIN) {
				struct sockaddr_in cliaddr;
				int addrlen = sizeof(cliaddr);
				int client_socket = accept(this->node_fd, (struct sockaddr *)&cliaddr, (socklen_t *)&addrlen);
				/* Adds the new connection into the first available slot in "pollfds"
				Because the for loop searches for the first slot with a fd == 0, 
				Whenever a client disconnects, their slot will be filled.
				*/
				for (int i = 1; i < MAX_CLIENTS; i++) { 
					if (pollfds[i].fd == 0) {
						clients++;
						printf("Accept succcess: %s. Currently %d nodes in the network.\n", inet_ntoa(cliaddr.sin_addr), clients);
						pollfds[i].fd = client_socket;
						pollfds[i].events = POLLIN | POLLPRI;
						pollfds[i].revents = 0;
						break;
					} 
				}
			}
			// Processing events from the connected nodes.
			for (int i = 1; i < MAX_CLIENTS; i++) {
				if (pollfds[i].fd > 0 && pollfds[i].revents & POLLIN) {
					int bufSize = read(pollfds[i].fd, buffer, sizeof(buffer));
					if (bufSize == -1 || bufSize == 0) { // Reading from the socket failed.
						pollfds[i].fd = 0;
						pollfds[i].events = 0;
						pollfds[i].revents = 0;
						clients--;
					} else {
						pollfds[i].revents = 0; // Zero out the revents so they arn't handled again.
						buffer[SOCKET_BUFFER_SIZE] = '\0';
						printf("From client: %s\n", buffer);
					}
				}
			}
		} 
	}
}

/* When this function is called, the node removes itself
from the network, closing socket connections with the other
nodes.
*/
void Node::terminate() {
	// Close the connections

}