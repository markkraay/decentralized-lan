#include "node.hpp"

#include "http/response.hpp"
#include "lan.hpp"
#include "network_utils.hpp"
#include "crypto.hpp"

#include <nlohmann/json.hpp>

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

#include <vector>
#include <chrono>
#include <regex>

using namespace std::chrono;
using json = nlohmann::json;

/* The node needs a private key to be instantiated
*/
Node::Node(const std::string& pkey_location, const std::string& blockchain_location) {
	this->pkey = crypto::initializeECDSAPrivateKey(pkey_location);
	this->blockchain = new Blockchain(blockchain_location);
}

/* When this function is called, the node 
joins the network, making itself available to other
nodes so that they to can connect.
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
	std::vector<int> nodes = lan::connect_to_nodes(30);
	for (auto node : nodes) {
		pollfds[clients].fd = node;
		pollfds[clients].events = POLLIN | POLLPRI;
		clients++;
	}

	char buffer[SOCKET_BUFFER_SIZE]; // For reading messages from the nodes
	auto next = system_clock::now();
	while (true) {
		if (system_clock::now() > next) {
			std::cout << "====================================" << std::endl;
			for (int i = 1; i < MAX_CLIENTS; i++) {
				if (pollfds[i].fd > 0) {
					std::cout << network_utils::resolve_fd(pollfds[i].fd) << std::endl;
				}
			}

			// Send a message to each socket
			for (int i = 1; i < MAX_CLIENTS; i++) {
				char *message = "Hello";
				if (pollfds[i].fd > 0) {
					if(send(pollfds[i].fd, message, sizeof(message), 0) == -1) {
						perror("send: ");
					}
				}
		}
			next = system_clock::now() + seconds(30);
		}

		// currentClient + 1 to include the node itself in the size
		int pollResult = poll(pollfds, clients, 5000); 
		if (pollResult > 0) { // Some events have been detected
			// Processing events for the server node.
			if (pollfds[0].revents & POLLIN) {
				struct sockaddr_in cliaddr;
				int addrlen = sizeof(cliaddr);
				int client_socket = accept(this->node_fd, (struct sockaddr *)&cliaddr, (socklen_t *)&addrlen);
				std::cout << "Accepted connection from: " << network_utils::resolve_fd(client_socket) << std::endl;
				/* Adds the new connection into the first available slot in "pollfds"
				Because the for loop searches for the first slot with a fd == 0, 
				Whenever a client disconnects, their slot will be filled.
				*/
				for (int i = 1; i < MAX_CLIENTS; i++) { 
					if (pollfds[i].fd == 0) {
						clients++;
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
						clients--;
					} else {
						buffer[SOCKET_BUFFER_SIZE] = '\0';
						std::cout << "Received data from " << network_utils::resolve_fd(pollfds[i].fd) << ". Resolving..." << std::endl;
						this->handle_buffer(pollfds[i].fd, std::string(buffer));
					}
					pollfds[i].revents = 0; // Zero out the revents so they arn't handled again.
				}
			}
		} 
	}
}

/* Handles HTTP messages and Node messages
*/
void Node::handle_buffer(int fd, const std::string& buffer_contents) {
	std::smatch matches;
	std::regex_search(buffer_contents, matches, std::regex(R"~(\w+)~"));
	char result[SOCKET_BUFFER_SIZE];
	// P2P Node Communication
	if (matches[0] == "QUERY_LATEST") { 

	} else if (matches[0] == "QUERY_ALL") {

	} else if (matches[0] == "RESPONSE_BLOCKCHAIN") {
	} else if (matches[0] == "QUERY_TRANSACTION_POOL") {

	} else if (matches[0] == "RESPONSE_TRANSACTION_POOL") {
	
	// HTTP Communication
	} else if (matches[0] == "GET" || matches[0] == "POST") { 
		std::cout << buffer_contents << std::endl;
		http::request request = network_utils::parse_http_request(buffer_contents);
		std::cout << request.to_string() << std::endl;

		http::response response;
		switch (request.method) {
			case http::request::GET:
				if (request.path == "/blocks") {
				} else if (request.path == "/peers") {
					// response.body = json::parse(this->getPeers());
				} else if (request.path == "/unspentTransactionOutputs") {
				} else if (request.path == "/myUnspentTransactionOutputs") {
				} else if (request.path == "/balance") {
				} else if (request.path == "/mineRawBlock") {
				} else if (request.path == "/mineBlock") {
				}else if (request.path == "/address") {
				} else if (request.path == "/mineTransaction") {
				} else if (request.path == "/sendTransaction") {
				} else if (request.path == "/stop") {
				} else {
					response = http::invalid_path_response;
				}
				break;
			case http::request::POST:
				if (request.path == "/pay") {

				} else if (request.path == "/balance") { 

				}
				break;
		}
		strcpy(result, response.to_string().c_str());
	} else { // Unknown
		strcpy(result, http::invalid_request_response.to_string().c_str());
	}

	write(fd, result, sizeof result);
}

/* When this function is called, the node removes itself
from the network, closing socket connections with the other
nodes.
*/
void Node::terminate() {
	// Close the connections

}

std::vector<std::string> Node::getPeers() {
	std::vector<std::string> fds;
	for (int i = 1; i < MAX_CLIENTS; i++) {
		int fd = this->pollfds[i].fd;
		if (fd > 0) {
			fds.push_back(network_utils::resolve_fd(fd));
		}
	}
	return fds;
}

Node::~Node() {
	EVP_PKEY_free(this->pkey);
	delete blockchain;
}