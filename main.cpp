#include "find_hosts.hpp"
#include "node.hpp"

// #include <nlohmann/json.hpp>

#include <fstream>
#include <set>
#include <string>
#include <vector>

// using json = nlohmann::json;

int main() {
	Node node = Node();
	node.start();

	// ping_broadcast(NULL);
	// Node node = Node();
	// node.start();

	// ping_broadcast(NULL);
	// std::vector<int> ips = connect_to_nodes();

	// std::vector<int> sock_fds;
	// for (const auto ip : ips) {
	// 	sock_fds.push_back(connect_to_node(ip, 3990));
	// }

	// Upon startup, the node first read's its copy of the Blockchain from disk.
	// std::ifstream local_blockchain_file("local_blockchain.json");
	// json local_blockchain_data = json::parse(local_blockchain_file);

	// Then, the node starts querying for other hosts on the network. If another node's copy of the
	// blockchain is correct, the node updates it's local copy of the blockchain and joins the network.
	// Otherwise, the node broadcasts it's copy of the blockchain to the rest of the network.
	// find_hosts();
	// Once a list of the hosts are found, we need to send a request to 
	// synchronize the chain. During chain synchronization, 

	// We will bind the program to a port, so that when we scan the network we can find Nodes.

	return 0;
}