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

protected: 

	bool isValidChain(); 
	void replaceChain(const Blockchain* blockchain); 
	int getDifficulty();
	int getAdjustedDifficulty();
	int size();
	int getAccumulatedDifficulty();
	Block getLatestBlock();

public:
	Blockchain();
	Blockchain(std::vector<Block> blocks, std::vector<UnspentTxOut> tx_outs);
	Blockchain(const Block& genesis_block); 
	Blockchain(const json& j); 

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