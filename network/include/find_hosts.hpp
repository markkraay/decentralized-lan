#pragma once

#include <string>
#include <vector>

void ping_broadcast(char *broadcast_address);
int connect_to_node(std::string ip, int port);
std::vector<int> connect_to_nodes();