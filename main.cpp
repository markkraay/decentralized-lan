#include "node.hpp"

int main() {
	Node node = Node("private_key.pem", "blockchain.json");
	node.start();

	return 0;
}