#pragma once

#include "blockchain.hpp"

#include "openssl/evp.h"

#include <sys/poll.h>

#include <string>

#define SOCKET_BUFFER_SIZE 1024
#define MAX_CLIENTS 500

/* A Node on the Network.
Each node on the network uses simple AF_INET + TCP 
sockets to communicate. All messages sent between nodes
are written in a special communication language.
*/ 
class Node {
private:
	EVP_PKEY *pkey;
	Blockchain *blockchain;
	int node_fd;
	struct pollfd pollfds[MAX_CLIENTS];

	void handle_buffer(int fd, const std::string& buffer_contents);

public: 
	Node(const std::string& pkey_location, const std::string& blockchain_location);

	void start();
	void terminate();
	~Node();


	std::vector<std::string> getPeers(); // Returns the connected IPs
};