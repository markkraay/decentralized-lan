#include "node.hpp"
#include "transaction.hpp"

#include <nlohmann/json.hpp>

#include <iostream>

#include "crypto.hpp"

using json = nlohmann::json;

int main() {
	Node node("private_key.pem", "blockchain.json");
	node.start();

	return 0;
}