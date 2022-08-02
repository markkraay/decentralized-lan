#include "crypto.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <string>
#include <memory>
#include <iostream>

// See: https://www.openssl.org/docs/man1.0.2/man3/EVP_PKEY_verify.html
// https://www.openssl.org/docs/man1.0.2/man3/EVP_PKEY_sign.html

// First, checks to see if the path to a private key has been passed in and the private key
// is present within the file. Then, checks the local directory to see if a private key is present.
// Finally, this function creates an encrypted private key on the user's disk if no private key
// can be found.
EVP_PKEY* crypto::initializeECDSAPrivateKey(const std::string& location) {
	FILE* pkey_file = fopen(location.c_str(), "r");
	if (pkey_file == NULL) { 
		return crypto::createECDSAPrivateKey(location);
	} else {
		fclose(pkey_file);
		return loadECDSAPrivateKey(location);
	}
};

EVP_PKEY* crypto::loadECDSAPrivateKey(const std::string& location) {
	std::cout << "Loading private key from " << location << std::endl;
	EVP_PKEY* pkey = NULL;
	FILE* pkey_file = fopen(location.c_str(), "r");
	if (pkey_file != NULL) {
		PEM_read_PrivateKey(pkey_file, &pkey, NULL, NULL);
	} else {
		std::cerr << "Could not open file '" << location << "' for reading the private key." << std::endl;
	}
	if (pkey == NULL) std::cerr << "Failed to obtain private key." << std::endl;
	fclose(pkey_file);
	return pkey;
}

EVP_PKEY* crypto::createECDSAPrivateKey(const std::string& location) {
	std::cout << "Creating private key at " << location << std::endl;
	EVP_PKEY* pkey = NULL;
	FILE* pkey_file = fopen(location.c_str(), "w");
	if (pkey_file != NULL) {
		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL); 
		if (!ctx) {
			perror("EVP_PKEY_CTX_new_id: ");
			exit(EXIT_FAILURE);
		}
		if (EVP_PKEY_keygen_init(ctx) <= 0) { 
			perror("EVP_PKEY_keygen_init: ");
			exit(EXIT_FAILURE);
		}

		if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
			perror("EVP_PKEY_keygen: ");
			exit(EXIT_FAILURE);
		}

		PEM_write_PrivateKey(
			pkey_file, // The file
			pkey, // The EVP_PKEY
			NULL, // Cipher for encrypting the key onto disk. One is not provided because of decryption errors.
			NULL, // The passphrase for unlocking the key. One is not provided because of decryption errors.
			8, // The length of the passphrase
			NULL, // Callback for requesting a password
			NULL // Data to pass to the callback
		);

		EVP_PKEY_CTX_free(ctx);
	} else {
		std::cerr << "Failed to create a file for saving the new private key" << std::endl;
	}
	if (pkey == NULL) std::cerr << "Failed to obtain private key." << std::endl;
	fclose(pkey_file);
	return pkey;
}

/* Signs a digest message that has been hashed with the SHA256 algorithm
*/
std::string crypto::signWithECDSA(const std::string& digest, EVP_PKEY* pkey) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (!ctx) {
		perror("EVP_PKEY_CTX_new: ");
		exit(EXIT_FAILURE);
	}
  if (EVP_PKEY_sign_init(ctx) <= 0) {
		perror("EVP_PKEY_sign_init: ");
		exit(EXIT_FAILURE);
	}
 
	size_t siglen;
	const unsigned char *md = reinterpret_cast<const unsigned char *>(digest.c_str());
	size_t mdlen = digest.size();
  // Determine buffer length
  if (EVP_PKEY_sign(ctx, NULL, &siglen, md, mdlen) <= 0) {
		perror("EVP_PKEY_sign determine buffer length: ");
		exit(EXIT_FAILURE);
	}
 
 	u_char* sig = (u_char *)OPENSSL_malloc(siglen);
  if (!sig) {
		perror("OPENSSL_malloc: ");
		exit(EXIT_FAILURE);
	}
 
  if (EVP_PKEY_sign(ctx, sig, &siglen, md, mdlen) <= 0) {
		perror("EVP_PKEY_sign: ");
		exit(EXIT_FAILURE);
	}

	std::string signature = std::string(reinterpret_cast<char *>(sig));
	free(sig);
	return signature;
}

bool crypto::verifyWithECDSA(const std::string& digest, const std::string& signature, EVP_PKEY* pkey) {
	const unsigned char *md = reinterpret_cast<const unsigned char *>(digest.c_str());
	size_t mdlen = digest.size();
	const unsigned char *sig = reinterpret_cast<const unsigned char *>(signature.c_str());
	size_t siglen = signature.size();

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx) {
		perror("EVP_PKEY_CTX_new: ");
		exit(EXIT_FAILURE);
	}

	if (EVP_PKEY_verify_init(ctx) <= 0) {
		perror("EVP_PKEY_verify_init: ");
		exit(EXIT_FAILURE);
	}

	if (EVP_PKEY_verify(ctx, sig, siglen, md, mdlen) <= 0) {
		return false; 
	}
	return true; 
}

std::string crypto::getPublicKey(EVP_PKEY *pkey) {
	// Get the size of the public key.
	size_t len;
	if (EVP_PKEY_get_raw_private_key(pkey, NULL, &len) <= 0) {
	}

	// Memory malloced for reading the key.
	auto public_key_ptr = (unsigned char*)malloc(sizeof(unsigned char) * len);
	if (EVP_PKEY_get_raw_public_key(pkey, public_key_ptr, &len) <= 0) {
	}

	std::string key(reinterpret_cast<char*>(public_key_ptr));
	free(public_key_ptr);
	return key;
}

void crypto::freeECDSAPrivateKey(EVP_PKEY *pkey) {
	EVP_PKEY_free(pkey);
	pkey = NULL;
}