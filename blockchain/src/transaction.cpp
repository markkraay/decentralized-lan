#include "transaction.hpp"

#include "crypto.hpp"

#include <iostream>

// ======================================================
// Constructors
// ======================================================
Transaction::Transaction() {}

Transaction::Transaction(std::vector<TxIn> tx_ins, std::vector<TxOut> tx_outs) {
	std::string content = "";
	for (auto tx_in : tx_ins) {
		content += tx_in.tx_out_id + std::to_string(tx_in.tx_out_index);
	}
	for (auto tx_out : tx_outs) {
		content += tx_out.address + std::to_string(tx_out.amount);
	}
	this->id = crypto::SHA256(content);
	this->tx_ins = tx_ins;
	this->tx_outs = tx_outs;
}

Transaction::Transaction(const json& j) : Transaction(
	j.at("tx_ins").get<std::vector<TxIn>>(),
	j.at("tx_outs").get<std::vector<TxOut>>()
) {}

// ======================================================
// Getters
// ======================================================
std::string Transaction::getId() const { return this->id; }
std::vector<TxIn> Transaction::getTxIns() const { return this->tx_ins; }
std::vector<TxOut> Transaction::getTxOuts() const { return this->tx_outs; }

json Transaction::to_json() const {
	json j;
	j["id"] = this->id;
	j["tx_ins"] = this->tx_ins;
	j["tx_outs"] = this->tx_outs;
	return j;
}

// ======================================================
// Validators
// ======================================================
bool Transaction::validateTxIn(TxIn tx_in, const std::vector<UnspentTxOut>& u_tx_outs) {
	// UnspentTxOut *referenced = nullptr;
	// for (auto u_tx_out : u_tx_outs) {
	// 	if (u_tx_out.tx_out_id == tx_in.tx_out_id && u_tx_out.tx_out_index == u_tx_out.tx_out_index) {
	// 		referenced = &u_tx_out;
	// 	}
	// }

	// if (referenced == nullptr) {
	// 	std::cerr << "validateTxIn: Referenced tx_out not found." << std::endl;
	// 	return false;
	// }

	// if (crypto::verifyWithECDSA(this->id, tx_in.signature, referenced->address)) {
	// 	std::cerr << "validateTxIn: Could not validate signature" << std::endl;
	// 	return false;
	// }

	return true;
}

// ======================================================
// Signer
// ======================================================
void Transaction::signTxIns(std::function<TxIn(TxIn)> signer) {
	std::for_each(this->tx_ins.begin(), this->tx_ins.end(), signer);
}