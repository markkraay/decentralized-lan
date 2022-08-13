#include "blockchain.hpp"

#include "crypto.hpp"

#include <iostream>
#include <algorithm>
#include <optional>
#include <chrono>
#include <vector>

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
	auto genesis_transaction = genesis_block.getData()[0];
	auto genesis_tx_in = genesis_transaction.getTxIns()[0];
	auto genesis_tx_out = genesis_transaction.getTxOuts()[0];

	this->unspent_tx_outs.push_back(UnspentTxOut{ 
		genesis_tx_in.tx_out_id, 
		genesis_tx_in.tx_out_index,
		genesis_tx_out.address,
		genesis_tx_out.amount,
	});
}

Blockchain::Blockchain(const json& j) {
	this->blocks = j.at("blocks").get<std::vector<Block>>();
	this->unspent_tx_outs = j.at("unspent_tx_outs").get<std::vector<UnspentTxOut>>();
	this->transaction_pool = j.at("transaction_pool").get<std::vector<Transaction>>();
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
	j["transaction_pool"] = this->transaction_pool;
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
// Public Setters
// ======================================================
void Blockchain::setTransactionPool(const std::vector<Transaction>& txs) { this->transaction_pool = txs; }

// ======================================================
// Validation Functions
// ======================================================
bool Blockchain::isValidChain() {
	for (int i = 1; i < blocks.size(); i++) {
		if (blocks[i].isValidNewBlock(blocks[i - 1])) {
			std::cerr << "isValidChain: isValidNewBlock" << std::endl;
			return false;
		}
	}
	return true;
}

// bool Blockchain::validateTransaction(const Transaction& tx) {
// 	for (auto& tx_in : tx.getTxIns()) {
// 		if (!this->validateTxIn(tx_in)) {
// 			std::cerr << "validateTransaction: invalid tx_in" << std::endl;
// 			return false;
// 		}
// 	}

// 	std::optional<UnspentTxOut> getTxInAmount([this->unspent_tx_outs](const TxIn& tx_in) {
// 		for (auto& u_tx_out : unspent_tx_outs) {
// 			if (u_tx_out.tx_out_id == tx_in.tx_out_id && u_tx_out.tx_out_index == tx_in.tx_out_index) return u_tx_out;
// 		}
// 	});

// 	int tx_in_amt = 0;
// 	for (auto& tx_in : tx.getTxIns()) {
// 		auto amount = getTxInAmount(tx_in);
// 		if (amount.has_value()) {
// 			tx_in_amt += amount.value();
// 		}
// 	}

// 	int tx_out_amt = 0;
// 	for (auto& tx_out : tx.getTxOuts()) {
// 		tx_out_amt += tx_out.amount;
// 	}

// 	if (tx_in_amt != tx_out_amt) {
// 		std::cerr << "validateTransaction: outs do not match ins" << std::endl;
// 		return false;
// 	}

// 	return true;
// }

// Checks if any of the tx_ins in the transaction being processed are already present
// within the pool
bool Blockchain::isValidTxForPool(const Transaction& tx) {
	// Obtain the transaction pool's inputs
	std::vector<TxIn> ins;
	for (auto& transaction : this->transaction_pool) {
		for (auto& in : transaction.getTxIns()) {
			ins.push_back(in);
		}
	}

	// Is one of the transaction's input stored in the transaction pool?
	for (auto& in : tx.getTxIns()) {
		for (auto& pool_in : ins) {
			if (in.tx_out_id == pool_in.tx_out_id && in.tx_out_index == pool_in.tx_out_index) {
				std::cerr << "isValidTxForPool: input already found in pool" << std::endl;
				return false;
			}
		}
	}

	return true;
}

bool Blockchain::validateTxIn(const TxIn& tx_in) {
	auto referenced = this->findReferencedUnspentTxOut(tx_in);
	if (referenced == nullptr) {
		std::cerr << "validateTxIn: referenced tx_out could not be found." << std::endl;
		return false;
	}

	auto address = referenced->address;
	// Need to be able to validate the signature by passing the key to this function somehow
	bool validSignature = true;
	if (!validSignature) {
		std::cerr << "validateTxIn: invalid signature" << std::endl;
		return false;
	}

	return true;
}

// ======================================================
// Blockchain Editing Functions
// ======================================================
void Blockchain::mineNextBlock() {
	auto previous_block = this->getLatestBlock();
	auto difficulty = this->getDifficulty();
	auto next_index = previous_block.getIndex() + 1;
	auto next_timestamp = Block::getCurrentTimestamp();
	auto new_block = findBlock(next_index, previous_block.getHash(), next_timestamp, this->transaction_pool, difficulty);
	this->blocks.push_back(new_block);
}

bool Blockchain::sendTransaction(EC_KEY* pkey, const std::string& receiver, int amount) {
	// Creating Transaction
	auto sender_address = crypto::getPublicKey(pkey);
	std::vector<TxIn> unsigned_tx_ins;
	int left_over_amount = 0;

	{
		auto unspent = this->getUnspentTxOutsGivenAddress(sender_address);

		// Filter the unspent transaction outputs that are already being used as inputs in the transaction pool
		unspent.erase(std::remove_if(unspent.begin(), unspent.end(), [&](const UnspentTxOut& u_tx_out) {
			for (auto& tx : this->transaction_pool) {
				for (auto& tx_in : tx.getTxIns()) {
					if (tx_in.tx_out_id == u_tx_out.tx_out_id && tx_in.tx_out_index == u_tx_out.tx_out_index) return true;
				}
			}
			return false;
 	  }), unspent.end());

		// Find the unspent transaction outputs which we will include as inputs in the transaction
		int current_amount = 0;
		for (auto& u_tx_out : unspent) {
			unsigned_tx_ins.push_back(TxIn { u_tx_out.tx_out_id, u_tx_out.tx_out_index, "" });
			current_amount += u_tx_out.amount;
			if (current_amount > amount) {
				left_over_amount = amount - current_amount;
			}
		}

		if (current_amount < amount) return false; // Not able to complete the transaction
	}

	// Create the transaction
	std::vector<TxOut> outs = {TxOut { receiver, amount }};
	if (left_over_amount > 0) outs.push_back(TxOut { sender_address, left_over_amount });

	Transaction tx(
		unsigned_tx_ins,
		outs
	);

	// Sign the transaction inputs
	tx.signTxIns([this, pkey, &tx](TxIn tx_in) {
		auto dataToSign = tx.getId();
		auto referenced = this->findReferencedUnspentTxOut(tx_in);
		if (referenced == nullptr) {
			throw std::invalid_argument("signTxIns: Could not find referenced tx_in");
		}
		std::string ref_address = referenced->address;
		if (crypto::getPublicKey(pkey) != ref_address) {
			throw std::invalid_argument("signTxIns: Sender address did not match referenced");
		}
		tx_in.signature = crypto::signWithECDSA(dataToSign, pkey);
		return tx_in;
	});
}

// bool Blockchain::processTransactions(const std::vector<Transaction>& txs, const std::vector<UnspentTxOut>& u_tx_outs, int block_index) {
// 	// Validate block transactions

// 	// Check for duplicate txIns.
// 	std::vector<TxIn> tx_ins;
// 	for (const auto& tx : txs) {
// 		for (const auto& tx_in : tx.getTxIns()) {
// 			for (const auto& seen : tx_ins) {
// 				if (seen.tx_out_id == tx_in.tx_out_id && seen.tx_out_index == seen.tx_out_index) return false;
// 				else tx_ins.push_back(tx_in);
// 			}
// 		}
// 	}
// }


// bool Blockchain::addToTransactionPool(const Transaction& tx) => {
//     if (!this->isValidTransaction(tx)) {
// 			std::cerr << "addToTransactionPool: validate transaction" << st::endl;
// 			return false;
//     }

//     if (!this->isValidTxForPool(tx)) {
// 			std::cerr << "addToTransactionPool: valid tx for pool" << st::endl;
// 			return false;
//     }

//     this->transaction_pool.push(tx);
// 		return true;
// };

// ======================================================
// Helpers Functions
// ======================================================
Block Blockchain::findBlock(int index, const std::string& previous_hash, int timestamp, const std::vector<Transaction>& txs, int difficulty) {
	int nonce = 0;
	while (true) {
		std::string hash = Block::calculateHash(index, previous_hash, timestamp, txs, difficulty, nonce);
		if (Block::hashMatchesDifficulty(hash, difficulty)) {
			return Block(index, hash, previous_hash, timestamp, txs, difficulty, nonce);
		}
		nonce++;
	}
}

UnspentTxOut* Blockchain::findReferencedUnspentTxOut(const TxIn& tx_in) {
	UnspentTxOut *referenced = nullptr;
	for (auto& u_tx_out : this->unspent_tx_outs) {
		if (u_tx_out.tx_out_id == tx_in.tx_out_id && u_tx_out.tx_out_index == tx_in.tx_out_index) referenced = &u_tx_out;
	}
	return referenced;
}