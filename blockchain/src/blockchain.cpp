#include "blockchain.hpp"

#include "crypto.hpp"

#include <iostream>
#include <algorithm>
#include <optional>
#include <chrono>

// ======================================================
// Constructors
// ======================================================
Blockchain::Blockchain() {}

Blockchain::Blockchain(std::vector<Block> blocks, std::vector<UnspentTxOut> tx_outs) { 
	this->blocks = blocks;  
	this->unspent_tx_outs = tx_outs;
}

Blockchain::Blockchain(const Block& genesis_block) {
	this->blocks.push_back(genesis_block);
}

Blockchain::Blockchain(const json& j) {
	this->blocks = j.at("blocks").get<std::vector<Block>>();
	this->unspent_tx_outs = j.at("unspent_tx_outs").get<std::vector<UnspentTxOut>>();
}

// ======================================================
// Public Getters
// ======================================================
std::vector<Block> Blockchain::getBlockchain() const { return this->blocks; }

std::vector<UnspentTxOut> Blockchain::getUnspentTxOuts() const { return  this->unspent_tx_outs; }

std::vector<UnspentTxOut> Blockchain::getUnspentTxOutsGivenAddress(const std::string& address) const {
	auto txs = this->getUnspentTxOuts();
	txs.erase(std::remove_if(txs.begin(), txs.end(), [&](const UnspentTxOut& tx) {
  	return tx.address != address;
  }), txs.end());
	return txs;
}

std::vector<Transaction> Blockchain::getTransactionPool() const { return this->transaction_pool; }

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

// ======================================================
// Protected Getters
// ======================================================
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

// ======================================================
// Validation Functions
// ======================================================
bool Blockchain::isValidChain() {
	for (int i = 1; i < blocks.size(); i++) {
		if (!isValidNewBlock(blocks.at(i), blocks.at(i - 1))) {
			return false;
		}
	}
	return true;
}

bool Blockchain::validateTransaction(const Transaction& tx) {


}

bool Blockchain::isValidTxForPool(const Transaction& tx) {

}

// ======================================================
// Blockchain Editing Functions
// ======================================================
void Blockchain::mineNextBlock() {
	if (this->transaction_pool.size() == 0) return;

	auto previous_block = this->getLatestBlock();
	auto difficulty = this->getDifficulty();
	auto next_index = previous_block.getIndex() + 1;
	auto next_timestamp = getCurrentTimestamp();
	auto new_block = findBlock(next_index, previous_block.getHash(), next_timestamp, this->transaction_pool, difficulty);
	this->blocks.push_back(new_block);
}

bool Blockchain::sendTransaction(const std::string& receiver, const std::string& sender, int amount, std::function<TxIn(TxIn)> signer) {
	auto address_unspent = this->getUnspentTxOutsGivenAddress(sender);
	// auto included = findTxOutsForAmount(amount, address_unspent);
	// Transaction t;
	// // Filter?

	// // Creating the transaction
	// if (included.has_value()) {
	// 	auto u_tx_outs = included.value().first;
	// 	auto left_over = included.value().second;

	// 	std::vector<TxIn> s_tx_ins;
	// 	for (auto u_tx_out : u_tx_outs) {
	// 		TxIn signed_tx_in = signer(TxIn { u_tx_out.tx_out_id, u_tx_out.tx_out_index });
	// 		s_tx_ins.push_back(signed_tx_in);
	// 	}
		
	// 	t = Transaction(
	// 		s_tx_ins, 
	// 		createTxOuts(receiver, sender, amount, left_over) 
	// 	);
	// } else {
	// 	return false;
	// }
}

// bool Blockchain::addToTransactionPool(Transaction tx) {
// 	if (!this->validateTransaction(tx)) {
// 		std::cerr << "addToTransactionPool: validateTransaction" << std::endl;
// 		return false;
// 	}
// 	if (!this->isValidTxForPool(tx)) {
// 		std::cerr << "addToTransactionPool: isValidTxForPool" << std::endl;
// 		return false;
// 	}
// 	this->transaction_pool.push_back(tx);
// 	return true;
// }

// ======================================================
// Helpers Functions
// ======================================================
// std::optional<std::pair<std::vector<UnspentTxOut>, int>> findTxOutsForAmount(int amount, const std::vector<UnspentTxOut>& u_tx_outs) {
// 	int current_amount = 0;
// 	std::vector<UnspentTxOut> included;
// 	for (auto u_tx_out : u_tx_outs) {
// 		included.push_back(u_tx_out);
// 		current_amount += u_tx_out.amount;
// 		if (current_amount >= amount) {
// 			int left_over_amount = current_amount - amount;
// 			return std::make_pair(included, left_over_amount);
// 		}
// 	}
// }

// std::vector<TxOut> createTxOuts(const std::string& receiver, const std::string& sender, int amount, int left_over) {
// 	std::vector<TxOut> tx_outs = { TxOut { receiver, amount }};
// 	if (left_over > 0) {
// 		tx_outs.push_back(TxOut { sender, left_over });
// 	}
// 	return tx_outs;
// }

bool isValidNewBlock(const Block& new_block, const Block& previous) {
	if (previous.getIndex() + 1 != new_block.getIndex()) {
		std::cerr << "isValidNewBlock: index" << std::endl;
		return false;
	} else if (previous.getHash() != new_block.getHash()) {
		std::cerr << "isValidNewBlock: hash" << std::endl;
		return false;
	} else if (!isValidTimestamp(new_block, previous)) {
		std::cerr << "isValidNewBlock: timestamp" << std::endl;
		return false;
	} else if (!hasValidHash(new_block)) {
		std::cerr << "isValidNewBlock: timestamp" << std::endl;
		return false;
	}

	return true;
}

bool isValidTimestamp(const Block& new_block, const Block& previous) {
	return previous.getTimestamp() - 60 < new_block.getTimestamp() && new_block.getTimestamp() - 60 < getCurrentTimestamp();
}

bool hasValidHash(const Block& block) {
	if (block.getHash() != calculateHash(block)) {
		std::cerr << "hasValidHash: hash" << std::endl;
		return false;
	} else if (!hashMatchesDifficulty(block.getHash(), block.getDifficulty())) {
		std::cerr << "hasValidHash: difficulty" << std::endl;
		return false;
	}

	return true;
}

int getCurrentTimestamp() { 
	auto now = std::chrono::system_clock::now();
	return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
}

Block findBlock(int index, const std::string& previous_hash, int timestamp, const std::vector<Transaction>& transactions, int difficulty) {
	int nonce = 0;
	while (true) {
		std::string hash = calculateHash(index, previous_hash, timestamp, transactions, difficulty, nonce);
		if (hashMatchesDifficulty(hash, difficulty)) {
			return Block(index, hash, previous_hash, timestamp, transactions, difficulty, nonce);
		}
		nonce++;
	}
}

std::string calculateHash(const Block& block) {
	return calculateHash(block.getIndex(), block.getHash(), block.getTimestamp(), block.getData(), block.getDifficulty(), block.getNonce());
}

std::string calculateHash(int index, const std::string& hash, int timestamp, const std::vector<Transaction>& transactions, int difficulty, int nonce) {
	std::string content = std::to_string(index) + hash + std::to_string(timestamp);
	for (auto t : transactions) {
		content += t.to_json().dump();
	}
	content += std::to_string(difficulty) + std::to_string(nonce);
	return crypto::SHA256(content);
}



bool hashMatchesDifficulty(std::string hash, int difficulty) {
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
	return (out.substr(0, difficulty)) == std::string('0', difficulty);
}