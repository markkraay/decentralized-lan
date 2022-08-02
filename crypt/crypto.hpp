#pragma once

#include <openssl/evp.h>

#include <string>

namespace crypto {
	std::string SHA256(const std::string& to_be_hashed);
	EVP_PKEY* createECDSAPrivateKey(const std::string& location);
	EVP_PKEY* loadECDSAPrivateKey(const std::string& location);
	EVP_PKEY* initializeECDSAPrivateKey(const std::string& location);
	std::string signWithECDSA(const std::string& data, EVP_PKEY* pkey);
	bool verifyWithECDSA(const std::string& digest, const std::string& sigature, EVP_PKEY* pkey);
	std::string getPublicKey(EVP_PKEY *pkey);
	void freeECDSAPrivateKey(EVP_PKEY *pkey);
}