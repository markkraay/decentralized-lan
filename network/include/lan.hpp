#pragma once

#include <string>
#include <map>

#define BROADCAST_ADDRESS "192.168.1.255"
#define PORT 3390

namespace lan {
	bool ping_broadcast();
	int connect_to_node(const std::string& ip);
	std::map<std::string, int> connect_to_nodes(int timeout_seconds);
};
