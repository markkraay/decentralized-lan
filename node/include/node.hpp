#pragma once

#include "blockchain.hpp"

#include "openssl/evp.h"

#include <sys/poll.h>

#include <string>
#include <memory>
#include <fstream>

#define SOCKET_BUFFER_SIZE 1024
#define MAX_CLIENTS 500
#define COINBASE_AMOUNT 50

/* A Node on the Network.
Each node on the network uses simple AF_INET + TCP 
sockets to communicate. All messages sent between nodes
are written in a special communication language.
*/ 
class Node {
private:
	EVP_PKEY *pkey;
	std::string pkey_location;
	Blockchain *blockchain;
	std::string blockchain_location;

	bool is_serving;
	std::string sniffing_device;
	int node_fd;
	struct pollfd pollfds[MAX_CLIENTS];

	void handleBuffer(int fd, const std::string& buffer_contents);
	void updateChain();
	bool confirmSender(int fd);

	// P2P 
	void handleQueryLatest(int fd);
	void handleQueryAll(int fd);
	void handleResponseBlockchain(int fd);
	void handleQueryTransactionPool(int fd);
	void handleResponseTransactionPool(int fd);

	// Broadcasts
	void broadcastTransactionPool();

	// GET
	void handleGetBlocks(int fd);
	void handleGetPeers(int fd);
	void handleGetUnspentTransactionOutputs(int fd, const json& j);
	void handleGetBalance(int fd, const json& j);
	void handleGetTransactionPool(int fd);
	void handleGetAddress(int fd);

	// POST
	void handleMineBlock(int fd);
	void handlePay(int fd, const json& j);

	// MISC
	void handleUnknownRequest(int fd);
	void handleUnauthorizedRequest(int fd);

public: 
	Node(const std::string& pkey_location, const std::string& blockchain_location);
	void start();

	void terminate();
	~Node();
};