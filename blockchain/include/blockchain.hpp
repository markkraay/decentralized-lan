#pragma once

#include "block.hpp"
#include "transaction.hpp"

#include <openssl/evp.h>
#include <nlohmann/json.hpp>

#include <functional>

using json = nlohmann::json;

#define DIFFICULTY_ADJUSTMENT_INTERVAL 10 // Number of blocks
#define BLOCK_GENERATION_INTERVAL 10 // Seconds

class Blockchain {
private:
	std::vector<Block> blocks;
	std::vector<UnspentTxOut> unspent_tx_outs;
	std::vector<Transaction> transaction_pool;

protected: 
	// Getters
	Block getLatestBlock();
	int size();
	int getDifficulty();
	int getAdjustedDifficulty();
	int getAccumulatedDifficulty();

	// Validators
	bool isValidChain(); 
	bool isValidTransaction(const Transaction& tx);
	bool isValidTxForPool(const Transaction& tx);
	bool validateTxIn(const TxIn& tx_in);

	// Blockchain editors
	bool addTransactionToPool(const Transaction& tx);

	// Helpers
	UnspentTxOut* findReferencedUnspentTxOut(const TxIn& tx_in);
	Block findBlock(int index, const std::string& previous_hash, int timestamp, const std::vector<Transaction>& txs, int difficulty);

public:
	Blockchain();
	Blockchain(std::vector<Block> blocks, std::vector<UnspentTxOut> tx_outs);
	Blockchain(const Block& genesis_block); 
	Blockchain(const json& j); 

	std::vector<Block> getBlockchain() const;
	std::vector<UnspentTxOut> getUnspentTxOuts() const;
	std::vector<UnspentTxOut> getUnspentTxOutsGivenAddress(const std::string& address) const;
	std::vector<Transaction> getTransactionPool() const;
	int getBalance(const std::string& address) const;

	void mineNextBlock();
	bool sendTransaction(EVP_PKEY* pkey, const std::string& receiver, int amount);

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