#include "block.hpp"

#include "crypto.hpp"

#include <chrono>
#include <iostream>

// ======================================================
// Constructors
// ======================================================
Block::Block() {}

Block::Block(int index, std::string hash, std::string previous_hash, int timestamp, std::vector<Transaction> data, int difficulty, int nonce) {
	this->index = index;
	this->hash = hash;
	this->previous_hash = previous_hash;
	this->timestamp = timestamp;
	this->data = data;
	this->difficulty = difficulty;
	this->nonce = nonce;
}

Block::Block(const json& j) : Block(
	j.at("index").get<int>(),
	j.at("hash").get<std::string>(),
	j.at("previous_hash").get<std::string>(),
	j.at("timestamp").get<int>(),
	j.at("data").get<std::vector<Transaction>>(),
	j.at("difficulty").get<int>(),
	j.at("nonce").get<int>()
) {}

// ======================================================
// Getters
// ======================================================
int Block::getIndex() const { return this->index; }
std::string Block::getHash() const { return this->hash; }
std::string Block::getPreviousHash() const { return this->previous_hash; }
int Block::getTimestamp() const { return this->timestamp; }
std::vector<Transaction> Block::getData() const { return this->data; }
int Block::getNonce() const { return this->nonce; }
int Block::getDifficulty() const { return this->difficulty; }

int Block::getCurrentTimestamp() { 
	auto now = std::chrono::system_clock::now();
	return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
}

json Block::to_json() const {
	json j;
	j["index"] = this->index;
	j["hash"] = this->hash;
	j["previous_hash"] = this->previous_hash;
	j["timestamp"] = this->timestamp;
	j["data"] = this->data;
	j["difficulty"] = this->difficulty;
	j["nonce"] = this->nonce;
	return j;
}

// ======================================================
// Validators
// ======================================================
bool Block::hasValidTimestamp(const Block& previous) {
	return previous.getTimestamp() - 60 < this->timestamp && this->timestamp - 60 < Block::getCurrentTimestamp();
}

bool Block::hasValidHash() {
	if (this->hash != this->calculateHash()) {
		std::cerr << "hasValidHash: hash" << std::endl;
		return false;
	} else if (!Block::hashMatchesDifficulty(this->hash, this->difficulty)) {
		std::cerr << "hasValidHash: difficulty" << std::endl;
		return false;
	}
	return true;
}

bool Block::isValidNewBlock(const Block& previous) {
	if (previous.getIndex() + 1 != this->index) {
		std::cerr << "isValidNewBlock: index" << std::endl;
		return false;
	} else if (previous.getHash() != this->hash) {
		std::cerr << "isValidNewBlock: hash" << std::endl;
		return false;
	} else if (!this->hasValidTimestamp(previous)) {
		std::cerr << "isValidNewBlock: timestamp" << std::endl;
		return false;
	} else if (!this->hasValidHash()) {
		std::cerr << "isValidNewBlock: timestamp" << std::endl;
		return false;
	}
	return true;
}

bool Block::hashMatchesDifficulty(std::string hash, int difficulty) {
	// Convert the hash to binary
	std::string out = "";
	for (char i : hash) {
		uint8_t n;
    if(i <= '9' and i >= '0')
      n = i - '0';
    else
      n = 10 + i - 'A';
    for (int8_t j = 3; j >= 0; --j)
      out.push_back((n & (1<<j))? '1':'0');
	}
	// Check if the first 'difficult' characters are equalt to '0'
	return out.substr(0, difficulty) == std::string(difficulty, '0');
}

// ======================================================
// Hashers
// ======================================================
std::string Block::calculateHash() {
	return Block::calculateHash(this->index, this->hash, this->timestamp, this->data, this->difficulty, this->nonce);
}

std::string Block::calculateHash(int index, const std::string& hash, int timestamp, const std::vector<Transaction>& transactions, int difficulty, int nonce) {
	std::string content = std::to_string(index) + hash + std::to_string(timestamp);
	for (auto t : transactions) {
		content += t.to_json().dump();
	}
	content += std::to_string(difficulty) + std::to_string(nonce);
	return crypto::SHA256(content);
}

