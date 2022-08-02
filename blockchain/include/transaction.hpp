#pragma once

#include <nlohmann/json.hpp>

#include <vector>
#include <string>

#define COINBASE_AMOUNT 50 // Initial number of coins in the blockchain

using json = nlohmann::json;

/* In ECDSA, the sender of coins will use their private key to generate a signature for 
a transaction. This signature can be obtained with the "signECDSA" function when provided
with a SHA256-hashed digest and the private key. Then, the recipient of the transaction
can use the sender's public key to verify that the coins were signed with the sender's 
public key.
*/
struct TxIn {
	std::string tx_out_id; // 
	int tx_out_index; 		 //
	std::string signature; // Signed with the sender's private key and is verifiable with the sender's public
};

struct TxOut {
	std::string address; // The public key of the owner
	int amount;					
};

struct UnspentTxOut {
	std::string tx_out;  //
	int tx_out_index;	   // 
	std::string address; // The public key of the owner 
	int amount;
};

class Transaction {
	std::string id;
	std::vector<TxIn> tx_ins;
	std::vector<TxOut> tx_outs;

public:
	Transaction();
	Transaction(std::string id, std::vector<TxIn> tx_ins, std::vector<TxOut> tx_outs);
	Transaction(const json& j);

	json to_json() const;
};

// ======================================================
// Json Serializers / Deserializers
// ======================================================

inline void to_json(json& j, const TxIn& t) {
	j["tx_out_id"] = t.tx_out_id;
	j["tx_out_index"] = t.tx_out_index;
	j["signature"] = t.signature;
}

inline void from_json(const json& j, TxIn& t) {
	t.tx_out_id = j.at("tx_out_id").get<std::string>();
	t.tx_out_index = j.at("tx_out_index").get<int>();
	t.signature = j.at("signature").get<std::string>();
}

inline void to_json(json& j, const TxOut& t) {
	j["address"] = t.address;
	j["amount"] = t.amount;
}

inline void from_json(const json& j, TxOut& t) {
	t.address = j.at("address").get<std::string>();
	t.amount = j.at("amount").get<int>();
}

inline void to_json(json& j, const UnspentTxOut& t) {
	j["address"] = t.address;
	j["amount"] = t.amount;
	j["tx_out"] = t.tx_out;
	j["tx_out_index"] = t.tx_out_index;
}

inline void from_json(const json& j, UnspentTxOut& t) {
	t.address = j.at("address").get<std::string>();
	t.amount = j.at("amount").get<int>();
	t.tx_out = j.at("tx_out").get<std::string>();
	t.tx_out_index = j.at("tx_out_index").get<int>();
}

inline void to_json(json& j, const Transaction& t) {
	j = t.to_json();
}

inline void from_json(const json& j, Transaction& t) {
	t = Transaction(j);
}