#include "node.hpp"

#include "http/response.hpp"
#include "lan.hpp"
#include "network_utils.hpp"
#include "crypto.hpp"
#include "bcl.hpp"

#include <nlohmann/json.hpp>

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <iostream>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

#include <algorithm>
#include <fstream>
#include <vector>
#include <chrono>
#include <regex>

using namespace std::chrono;
using json = nlohmann::json;

/* The node needs a private key and an initial copy of the blockchain to be instantiated
The node first checks if there is a file on disc that contains a copy of the last scene blockchain. 
If such file exists, the node reads it contents and initializes its copy of the blockchain accordingly.
Otherwise, the node creates its own copy of the blockchain and writes it to disc.
*/ 
Node::Node(const std::string& pkey_location, const std::string& blockchain_location) {
	this->pkey = crypto::initializeECDSAPrivateKey(pkey_location);
	this->blockchain_location = blockchain_location;
	std::fstream file(blockchain_location, std::fstream::in);

	if (file.is_open()) {
		try {
			std::cout << "Successfully obtained last seen copy of blockchain from " << blockchain_location << std::endl;
			this->blockchain = new Blockchain(json::parse(file));
			return;
		} catch (json::parse_error& error) {
			std::cerr << "Could not parse the blockchain at " << blockchain_location << ". Creating a new copy using the following genesis block: ";
		}
	} else {
		std::cout << "Could not find a copy of the blockchain on disk... Creating a new one using the following genesis block: ";
	}

	TxIn genesis_input{"", 0, ""};
	TxOut genesis_output{crypto::getPublicKey(this->pkey), COINBASE_AMOUNT};
	std::cout << crypto::getPublicKey(this->pkey) << std::endl;
	Block genesis(
		0, 
		"91a73664bc84c0baa1fc75ea6e4aa6d1d20c5df664c724e3159aefc2e1186627", 
		"", 
		Block::getCurrentTimestamp(), 
		{ Transaction({genesis_input}, {genesis_output})},
		0,
		0
	);

	std::cout << genesis.to_json() << std::endl;
	this->blockchain = new Blockchain(genesis);
	file.close();
	this->updateChain();
}

/* Writes the current blockchain's data to the file pointed to by 'blockchain_download'
*/
void Node::updateChain() {
	std::fstream file(this->blockchain_location, std::fstream::out);
	file << this->blockchain->to_json();
	file.close();
}

/* Confirms that the LAN address of the connected file descriptor
matches that of the host machine.
*/
bool Node::confirmSender(int fd) {
	return network_utils::resolve_fd(fd) == network_utils::get_ipv4_lan_address(this->sniffing_device);
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
	std::pair<std::string, std::vector<int>> result = lan::connect_to_nodes(1);
	this->sniffing_device = result.first;
	auto nodes = result.second;
	for (auto node : nodes) {
		pollfds[clients].fd = node;
		pollfds[clients].events = POLLIN | POLLPRI;
		clients++;
	}

	this->is_serving = true;
	char buffer[SOCKET_BUFFER_SIZE]; // For reading messages from the nodes
	auto next = system_clock::now();
	while (this->is_serving) {
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
						buffer[bufSize] = '\0';
						std::cout << "Received data from " << network_utils::resolve_fd(pollfds[i].fd) << ". Resolving..." << std::endl;
						this->handleBuffer(pollfds[i].fd, std::string(buffer));
					}
					pollfds[i].revents = 0; // Zero out the revents so they arn't handled again.
				}
			}
		} 
	}
}

/* Handles HTTP messages and Node messages
*/
void Node::handleBuffer(int fd, const std::string& buffer_contents) {
	std::smatch matches;
	std::regex_search(buffer_contents, matches, std::regex(R"~(\w+)~"));
	// P2P Node Communication
	if (matches[0] == "GET" || matches[0] == "POST") { 
		http::request request = network_utils::parse_http_request(buffer_contents);
		std::cout << request.to_string() << std::endl;

		switch (request.method) {
			case http::request::method::GET:
				if (request.path == "/blocks") {
					this->handleGetBlocks(fd);
				} else if (request.path == "/peers") {
					this->handleGetPeers(fd);
				} else if (request.path == "/unspentTransactionOutputs") { // FIX
					this->handleGetUnspentTransactionOutputs(fd, request.payload);
				} else if (request.path == "/balance") { // FIX
					this->handleGetBalance(fd, request.payload);
				} else if (request.path == "/address") {
					this->handleGetAddress(fd);
				} else if (request.path == "/transactionPool") {
					this->handleGetTransactionPool(fd);
				} else if (request.path == "/stop") {
					this->terminate();
				} else {
					this->handleUnknownRequest(fd);
				}
				break;
			case http::request::method::POST:
				if (request.path == "/pay") { // FIX
					this->handlePay(fd, request.payload);
				} else if (request.path == "/mineBlock") {
					this->handleMineBlock(fd);
				} else {
					this->handleUnknownRequest(fd);
				}
				break;
		}
	} else {
		try {
			P2P_Msg msg = json::parse(buffer_contents);
			switch (msg.type) {
				case P2P_Msg::MessageType::QUERY_ALL:
					this->handleQueryAll(fd);
					break;
				case P2P_Msg::MessageType::QUERY_LATEST:
					this->handleQueryLatest(fd);
					break;
				case P2P_Msg::MessageType::QUERY_TRANSACTION_POOL:
					this->handleQueryTransactionPool(fd);
					break;
				case P2P_Msg::MessageType::RESPONSE_BLOCKCHAIN:
					this->handleResponseBlockchain(fd);
					break;
				case P2P_Msg::MessageType::RESPONSE_TRANSACTION_POOL:
					this->handleResponseTransactionPool(fd);
					break;
			}
		} catch(json::parse_error& error) {
			std::cerr << "Unknown request: " << buffer_contents << std::endl;
			this->handleUnknownRequest(fd);
		}
	}
}

/* When this function is called, the node removes itself
from the network, closing socket connections with the other
nodes.
*/
void Node::terminate() {
	this->is_serving = false;
}

Node::~Node() {
	crypto::freeECDSAPrivateKey(this->pkey);
}

// ======================================================
// P2P Communication Handles
// ======================================================
void Node::handleQueryLatest(int fd) {

}

void Node::handleQueryAll(int fd) {
	// char message_buffer[SOCKET_BUFFER_SIZE];
	
	// // Write each block to the buffer
	// for (const auto& block : this->blockchain->getBlockchain()) {
	// 	std::string block_data = block.to_json();
	// 	strcpy(message_buffer, block_data.c_str());
		
	// 	if (write(fd, message_buffer, block_data.size()) == -1) {
	// 		perror("handleQueryAll: write");
	// 		std::cerr << "Could not write the whole blockchain to the querying node" << std::endl;
	// 	}
	// }
}

void Node::handleResponseBlockchain(int fd) {

}

void Node::handleQueryTransactionPool(int fd) {

}

void Node::handleResponseTransactionPool(int fd) {
	std::vector<Transaction> received_pool;
	char message_buffer[SOCKET_BUFFER_SIZE];
	int num_bytes = 0;
	std::smatch matches;

	while (true) {
		if ((num_bytes = read(fd, message_buffer, SOCKET_BUFFER_SIZE)) == -1) {
			perror("handleResponseTransactionPool: read");
			break;
		}
		message_buffer[num_bytes] = '\0';

		try { 
			P2P_Msg msg = json::parse(std::string(message_buffer));
			if (msg.type != P2P_Msg::MessageType::RESPONSE_TRANSACTION_POOL) {
				std::cerr << "Received the wrong P2P message" << std::endl;
				break;
			} else {
				std::cout << msg.data << std::endl;
			}
		} catch(json::parse_error& error) {
			return;
		}
	}
}

// ======================================================
// P2P Broadcast
// ======================================================
void Node::broadcastTransactionPool() {
	char message_buffer[SOCKET_BUFFER_SIZE];
	P2P_Msg msg;
	msg.type = P2P_Msg::MessageType::RESPONSE_TRANSACTION_POOL;

	// This would be more efficient if I could launch a thread for 
	// each node to write the transaction pool
	for (int i = 1; i < MAX_CLIENTS; i++) {
		int fd = this->pollfds[i].fd;
		if (fd > 0) {
			// Write the transaction pool
			for (const auto& tx : this->blockchain->getTransactionPool()) {
				msg.data = tx.to_json();
				auto result = std::string(json(msg));
				strcpy(message_buffer, result.c_str());
				write(fd, message_buffer, result.size());
			}
		}
	}
}

// ======================================================
// HTTP GET Handles
// ======================================================
void Node::handleGetBlocks(int fd) {
	char message_buffer[SOCKET_BUFFER_SIZE];

	auto blocks = this->blockchain->getBlockchain();
	std::vector<Block> last_5(blocks.end() - std::min(5, (int)blocks.size()), blocks.end());
	Blockchain new_chain(last_5, this->blockchain->getUnspentTxOuts());
	std::string body = new_chain.to_json().dump();

	auto result = http::response_200(body).to_string();
	strcpy(message_buffer, result.c_str());
	write(fd, message_buffer, result.size());
}

void Node::handleGetPeers(int fd) {
	char message_buffer[SOCKET_BUFFER_SIZE];

	std::vector<std::string> ips;
	for (int i = 1; i < MAX_CLIENTS; i++) {
		int fd = pollfds[i].fd;
		if (fd > 0) {
			ips.push_back(network_utils::resolve_fd(fd));
		}
	}
	json j;
	j["ips"] = ips;
	std::string body = j.dump();

	auto result = http::response_200(body).to_string();
	strcpy(message_buffer, result.c_str());
	write(fd, message_buffer, result.size());
}

void Node::handleGetUnspentTransactionOutputs(int fd, const json& j) {
	char message_buffer[SOCKET_BUFFER_SIZE];

	try {
		auto address = j.at("address").get<std::string>(); 
		std::vector<UnspentTxOut> u;

		if (address != "") {
			u = this->blockchain->getUnspentTxOutsGivenAddress(address);
		} else {
			u = this->blockchain->getUnspentTxOuts();
		}
		std::string body = json(u).dump();

		auto result = http::response_200(body).to_string();
		strcpy(message_buffer, result.c_str());
		write(fd, message_buffer, result.size());
	} catch (json::parse_error& error) {
		auto result = http::response_500("Expecting 'Content-Type': 'application/json' and '{'address': string}'").to_string();
		strcpy(message_buffer, result.c_str());
		write(fd, message_buffer, result.size());
	}
}

void Node::handleGetBalance(int fd, const json& j) {
	char message_buffer[SOCKET_BUFFER_SIZE];
	std::string result;

	try { 
		auto address = j.at("address").get<std::string>();

		int total = 0;
		for (auto u_tx_out : this->blockchain->getUnspentTxOuts()) {
			if (u_tx_out.address == address) {
				total += u_tx_out.amount;
			}
		}

		json j;
		j["balance"] = total;
		std::string body = j.dump();
	
		result = http::response_200(body).to_string();
	} catch(json::exception& error) {
		result = http::response_500("Requires 'Content-Type': 'application/json' and '{'address': string}'").to_string();
	}

	strcpy(message_buffer, result.c_str());
	write(fd, message_buffer, result.size());
}

void Node::handleGetAddress(int fd) {
	char message_buffer[SOCKET_BUFFER_SIZE];

	/* For the public key to be returned, the user must cURL the endpoint of the node
	that is currently running on their own machine. For example, if a node is being hosted
	on 192.168.1.211, the user must curl this address from the same machine to get their public key.
	*/
	auto requesting_address = network_utils::resolve_fd(fd);
	auto host_address = network_utils::get_ipv4_lan_address(this->sniffing_device);
	if (requesting_address == host_address) {
		auto result = http::response_200(crypto::getPublicKey(this->pkey)).to_string();
		strcpy(message_buffer, result.c_str());
		write(fd, message_buffer, result.size());
	} else {
		this->handleUnauthorizedRequest(fd);
	}
}

void Node::handleGetTransactionPool(int fd) {
	char message_buffer[SOCKET_BUFFER_SIZE];

	json j;
	j["transaction_pool"] = this->blockchain->getTransactionPool();
	std::string body = j.dump();

	auto result = http::response_200(body).to_string();
	strcpy(message_buffer, result.c_str());
	write(fd, message_buffer, result.size());
}

void Node::handleUnknownRequest(int fd) {
	char message_buffer[SOCKET_BUFFER_SIZE];

	auto result = http::invalid_path_response.to_string();
	strcpy(message_buffer, result.c_str());
	write(fd, message_buffer, result.size());
}

void Node::handleUnauthorizedRequest(int fd) {
	char message_buffer[SOCKET_BUFFER_SIZE];

	auto result = http::unauthorized_request_response.to_string();
	strcpy(message_buffer, result.c_str());
	write(fd, message_buffer, result.size());
}

// ======================================================
// HTTP POST Handles
// ======================================================
void Node::handleMineBlock(int fd) {
	char message_buffer[SOCKET_BUFFER_SIZE];

	if (!this->confirmSender(fd)) {
		this->handleUnauthorizedRequest(fd);
		return;
	}

	this->blockchain->mineNextBlock();
}

void Node::handlePay(int fd, const json& j) {
	char message_buffer[SOCKET_BUFFER_SIZE];

	if (!this->confirmSender(fd)) {
		this->handleUnauthorizedRequest(fd);
		return;
	}

	std::string result;
	bool success = false;
	try {
		std::string receiver = j.at("address").get<std::string>();
		int amount = j.at("amount").get<int>();
		if (this->blockchain->sendTransaction(this->pkey, receiver, amount)) {
			result = http::response_200("Succesfully sent funds.").to_string();
			success = true;
		} else {
			result = http::response_200("Unable to send funds.").to_string();
		}
	} catch(json::exception error) {
		result = http::response_500("Expection 'Content-Type': 'application/json' and '{'address': 'string', 'amount': int'}'").to_string();
	}
	strcpy(message_buffer, result.c_str());
	write(fd, message_buffer, result.size());

	if (success) this->broadcastTransactionPool();
}