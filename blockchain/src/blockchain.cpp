#include "blockchain.hpp"

#include "crypto.hpp"

#include <iostream>
#include <fstream>

Blockchain::Blockchain() {}

Blockchain::Blockchain(const Block& genesis_block) {
	this->blocks.push_back(genesis_block);
}

Blockchain::Blockchain(const json& j) {
	this->blocks = std::vector<Block>{};
	// this->blocks = j.at("blocks").get<std::vector<Block>>();
	this->unspent_tx_outs = j.at("unspent_tx_outs").get<std::vector<UnspentTxOut>>();
}

// Public Getters 
std::vector<Block> Blockchain::getBlockchain() const { return this->blocks; }

std::vector<UnspentTxOut> Blockchain::getUnspentTxOuts() const { return  this->unspent_tx_outs; }

int Blockchain::getBalance(const std::string& address) const {
	int total = 0;
	for (UnspentTxOut u_tx_out : this->unspent_tx_outs) {
		if (u_tx_out.address == address) {
			total += u_tx_out.amount;
		}
	}
	return total;
}

json Blockchain::to_json() const {
	json j;
	j["blocks"] = this->blocks;
	j["unspent_tx_outs"] = this->unspent_tx_outs;
	return j;
}


// Protected Getters
Block Blockchain::getLatestBlock() { return this->blocks.back(); }
int Blockchain::size() { return this->blocks.size(); }

/* Returns the difficulty of the blockchain. The difficulty is defined as the number
of zeros that prefix binary form of the hash. For example, a hash with a binary form of 
'000110' would have a difficulty of 3, because 3 zeros prefix it.
This calculation only occurs every N blocks, which is designated by the DIFFICULTY_ADJUSTMENT_INTERVAL
*/
int Blockchain::getDifficulty() {
	Block latest_block = this->getLatestBlock();

	// We only adjust the block difficulty every DIFFICULTY_ADJUSTMENT_INTERVAL blocks.
	if (latest_block.getIndex() % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 && latest_block.getIndex() != 0) {
		return this->getAdjustedDifficulty();
	}
	return latest_block.getDifficulty();
}

int Blockchain::getAdjustedDifficulty() {
	Block latest_block = this->getLatestBlock();
	Block& previous_adjustment_block = this->blocks.at(blocks.size() - DIFFICULTY_ADJUSTMENT_INTERVAL);
	
	int time_expected = BLOCK_GENERATION_INTERVAL * DIFFICULTY_ADJUSTMENT_INTERVAL;
	// Time take to generate the last DIFFICULTY_ADJUSTMENT_INTERVAL blocks.
	int time_taken = latest_block.getTimestamp() - previous_adjustment_block.getTimestamp();

	int base = previous_adjustment_block.getDifficulty();
	if (time_taken < time_expected / 2) {
		return base - 1;
	} else if (time_taken > time_expected * 2) {
		return base + 1;
	}
	return base;
}

// void Blockchain::generateNextBlock()

// Block Blockchain::generateBlockWithTransaction()

/* Determines if a blockchain is valid by analyzing the sequence of block
it consists of.
*/ 
bool Blockchain::isValidChain() {
	for (int i = 1; i < blocks.size(); i++) {
		// if (!isValidNewBlock(blocks.at(i), blocks.at(i - 1))) {
		// 	return false;
		// }
	}
	return true;
}
