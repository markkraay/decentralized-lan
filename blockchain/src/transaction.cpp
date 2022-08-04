#include "transaction.hpp"

// ======================================================
// Constructors
// ======================================================
Transaction::Transaction() {}

Transaction::Transaction(std::string id, std::vector<TxIn> tx_ins, std::vector<TxOut> tx_outs) {
	this->id = id;
	this->tx_ins = tx_ins;
	this->tx_outs = tx_outs;
}

Transaction::Transaction(const json& j) : Transaction(
	j.at("id").get<std::string>(),
	j.at("tx_ins").get<std::vector<TxIn>>(),
	j.at("tx_outs").get<std::vector<TxOut>>()
) {}

// ======================================================
// Getters
// ======================================================
json Transaction::to_json() const {
	json j;
	j["id"] = this->id;
	j["tx_ins"] = this->tx_ins;
	j["tx_outs"] = this->tx_outs;
	return j;
}