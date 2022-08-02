#include "node.hpp"
#include "transaction.hpp"

#include <nlohmann/json.hpp>

#include <iostream>

using json = nlohmann::json;

int main() {
	// std::string pkey_location, blockchain_location;
	// std::cout << "Please enter the location of your private key, otherwise 'private_pkey.pem' is used. ";
	// std::cin >> pkey_location;
	// std::cout << "Please enter the location of your previous copy of the blockchain, otherwise 'blockchain.json' is used. ";
	// std::cin >> blockchain_location;

	// Node node = Node(pkey_location, blockchain_location);
	// node.start();

	Block genesis(0, "91a73664bc84c0baa1fc75ea6e4aa6d1d20c5df664c724e3159aefc2e1186627", "", 1465154705, std::vector<Transaction>{}, 0, 0);
	Blockchain chain(genesis);
	std::cout << chain.to_json() << std::endl;


	return 0;
}