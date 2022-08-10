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

	// Getters
	int getIndex() const;
	std::string getHash() const;
	std::string getPreviousHash() const;
	int getTimestamp() const;
	std::vector<Transaction> getData() const;
	int getNonce() const;
	int getDifficulty() const;
	static int getCurrentTimestamp();

	// Validators
	bool hasValidTimestamp(const Block& previous);
	bool hasValidHash();
	bool isValidNewBlock(const Block& previous);
	static bool hashMatchesDifficulty(std::string hash, int difficulty);

	// Hashers
	std::string calculateHash();
	static std::string calculateHash(int index, const std::string& hash, int timestamp, const std::vector<Transaction>& transactions, int difficulty, int nonce);

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