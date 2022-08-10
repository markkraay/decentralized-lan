#pragma once

#include <nlohmann/json.hpp>

#include <string>

using json = nlohmann::json;

struct P2P_Msg {
	enum class MessageType {
		QUERY_LATEST, QUERY_ALL, RESPONSE_BLOCKCHAIN, QUERY_TRANSACTION_POOL, RESPONSE_TRANSACTION_POOL
	};

	MessageType type;
	json data;
};

inline void to_json(json& j, const P2P_Msg& msg) {
	j["type"] = msg.type;
	j["data"] = msg.data;
}

inline void from_json(const json& j, P2P_Msg& msg) {
	msg.type = j.at("type").get<P2P_Msg::MessageType>();
	msg.data = j.at("data").get<json>();
}