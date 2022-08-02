#pragma once

#include <nlohmann/json.hpp>

#include "transaction.hpp"

#include <vector>
#include <string>

using json = nlohmann::json;

class Block {
private:
	int index;
	std::string hash;
	std::string previous_hash;
	int timestamp;
	std::vector<Transaction> data;
	int difficulty;
	int nonce;

public:
	Block();
	Block(int index, std::string hash, std::string previous_hash, 
		int timestamp, std::vector<Transaction> transactions, 
		int difficulty, int nonce
	);
	Block(const json& j);

	int getIndex() const;
	std::string getHash() const;
	std::string getPreviousHash() const;
	int getTimestamp() const;
	std::vector<Transaction> getData() const;
	int getNonce() const;
	int getDifficulty() const;

	json to_json() const;
};

// ======================================================
// Json Serializers / Deserializers
// ======================================================

inline void to_json(json& j, const Block& b) {
	j = b.to_json();
}

inline void from_json(const json& j, Block& b) {
	b = Block(j);
}