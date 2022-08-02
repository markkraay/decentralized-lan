#pragma once

#include "block.hpp"
#include "transaction.hpp"

#include <nlohmann/json.hpp>

using json = nlohmann::json;

#define DIFFICULTY_ADJUSTMENT_INTERVAL 10 // Number of blocks
#define BLOCK_GENERATION_INTERVAL 10 // Seconds

class Blockchain {
private:
	std::vector<Block> blocks;
	std::vector<UnspentTxOut> unspent_tx_outs;

/* These should be accessible to other instances of the blockchain, but
inaccessible everywhere else.
*/
protected: 

	bool isValidChain(); // Determines if a blockchain is valid
	void replaceChain(const Blockchain* blockchain); // Compares two chains and replaces the current one's data if the other chain is superior
	int getDifficulty();
	int getAdjustedDifficulty();
	int size();
	int getAccumulatedDifficulty();
	Block getLatestBlock();

// These are the functions that are accessible to the node.
public:
	Blockchain();
	Blockchain(const Block& genesis_block); // A genesis block
	Blockchain(const json& j); // JSON file on the disk

	std::vector<Block> getBlockchain() const;
	std::vector<UnspentTxOut> getUnspentTxOuts() const;
	int getBalance(const std::string& address) const;

	json to_json() const;
};

// ======================================================
// Json Serializers / Deserializers
// ======================================================

inline void to_json(json& j, const Blockchain& b) {
	j = b.to_json();
}

inline void from_json(const json& j, Blockchain &b) {
	b = Blockchain(j);
}