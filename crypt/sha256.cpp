#include "crypto.hpp"

#include <openssl/sha.h>

#include <sstream>
#include <iomanip>

std::string crypto::SHA256(const std::string& to_be_hashed) {
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, to_be_hashed.c_str(), to_be_hashed.size());
	SHA256_Final(hash, &sha256);
	std::stringstream ss;
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		ss << std::hex << std::setw(2) << std::setfill('0') << int(hash[i]);
	}
	return ss.str();
}