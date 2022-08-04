#include "block.hpp"

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