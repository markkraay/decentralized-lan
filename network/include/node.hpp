#pragma once

#define PORT 3390
#define SOCKET_BUFFER_SIZE 1024
#define MAX_CLIENTS 500

#include <map>
#include <mutex>
#include <sys/poll.h>

/* A Node on the Network.
Each node on the network uses simple AF_INET + TCP 
sockets to communicate. All messages sent between nodes
are written in a special communication language.
*/ 
class Node {
private:
	int node_fd;
	struct pollfd pollfds[MAX_CLIENTS];
	bool is_online;
	void beginAcceptingConnections();
	void beginReadingInputs();

public: 
	Node();
	void start();
	void terminate();
};