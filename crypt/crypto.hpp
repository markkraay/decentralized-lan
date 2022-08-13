#pragma once

#include <openssl/ec.h>

#include <string>

namespace crypto {
	std::string SHA256(const std::string& to_be_hashed);
	EC_KEY* createECDSAPrivateKey(const std::string& location);
	EC_KEY* loadECDSAPrivateKey(const std::string& location);
	EC_KEY* initializeECDSAPrivateKey(const std::string& location);
	std::string signWithECDSA(const std::string& data, EC_KEY* pkey);
	bool verifyWithECDSA(const std::string& digest, const std::string& b64_sigature, EC_KEY* pkey);
	std::string getPublicKey(EC_KEY*pkey);
	void freeECDSAPrivateKey(EC_KEY*pkey);
	std::string Base64Encode(const std::string& buffer);
	std::string Base64Decode(const std::string& b64_input);
}