#include "crypto.hpp"

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <vector>
#include <string>
#include <memory>
#include <iostream>

/* We are using standarad C++ strings throughout the rest of the codebase. However,
all of the OPENSSL functions use C styled strings. Since some of these strings contain
null-bytes, a standard .c_str() does not work. Make sure to accompany this call with free
*/
char * std_to_c_string(const std::string& std) {
	char *sig = (char *)malloc(std.size() + 1);
	std::vector<char> sig_chars(std.begin(), std.end());
	for (int i = 0; i < std.size(); i++) {
		sig[i] = sig_chars[i];
	}
	sig[std.size()] = '\0';
	return sig;
}

// First, checks to see if the path to a private key has been passed in and the private key
// is present within the file. Then, checks the local directory to see if a private key is present.
// Finally, this function creates an encrypted private key on the user's disk if no private key
// can be found.
EC_KEY* crypto::initializeECDSAPrivateKey(const std::string& location) {
	FILE* pkey_file = fopen(location.c_str(), "r");
	if (pkey_file == NULL) { 
		return crypto::createECDSAPrivateKey(location);
	} else {
		fclose(pkey_file);
		return loadECDSAPrivateKey(location);
	}
};

EC_KEY* crypto::loadECDSAPrivateKey(const std::string& location) {
	std::cout << "Loading private key from " << location << std::endl;
	EC_KEY* ec_key = NULL;
	FILE* pkey_file = fopen(location.c_str(), "r");
	if (pkey_file != NULL) {
		PEM_read_ECPrivateKey(pkey_file, &ec_key, NULL, NULL);
	} else {
		std::cerr << "Could not open file '" << location << "' for reading the private key." << std::endl;
	}
	if (ec_key == NULL) std::cerr << "Failed to obtain private key." << std::endl;
	fclose(pkey_file);
	return ec_key;
}

EC_KEY* crypto::createECDSAPrivateKey(const std::string& location) {
	std::cout << "Creating private key at " << location << std::endl;
	FILE* key_file = fopen(location.c_str(), "w");
	EC_KEY* ec_key;
	EC_GROUP* ec_group;

	if (key_file != NULL) {
		ec_key = EC_KEY_new();
		if (ec_key == NULL) {
			std::cerr << "Failed to create key" << std::endl;
			goto file_close;
		}

		ec_group = EC_GROUP_new_by_curve_name(NID_secp192k1);
		if (ec_group == NULL) {
			std::cerr << "Failed to create ec_group" << std::endl;
			goto ec_key_free;
		}

		if (EC_KEY_set_group(ec_key, ec_group) != 1) {
			std::cerr << "Failed to set key group" << std::endl;
			goto ec_group_free;
		}
			
		if (EC_KEY_generate_key(ec_key) != 1) {
			std::cerr << "Failed to generate key" << std::endl;
			goto ec_group_free;
		}

		if (PEM_write_ECPrivateKey(
			key_file, // The file
			ec_key, // The EC_KEY
			NULL, // Cipher for encrypting the key onto disk. One is not provided because of decryption errors.
			NULL, // The passphrase for unlocking the key. One is not provided because of decryption errors.
			8, // The length of the passphrase
			NULL, // Callback for requesting a password
			NULL // Data to pass to the callback
		) != 1) {
			std::cerr << "Failed to write EC private key to file" << std::endl;
			goto ec_group_free;
		}

		// Success
		EC_GROUP_free(ec_group);
		fclose(key_file);
		return ec_key;

		// Failure
		ec_group_free:
		EC_GROUP_free(ec_group);
		ec_key_free:
		EC_KEY_free(ec_key);
		file_close:
		fclose(key_file);
		return nullptr;
	} else {
		std::cerr << "Failed to create a file for saving the new private key" << std::endl;
		return nullptr;
	}
}

// Signs a digest message
std::string crypto::signWithECDSA(const std::string& digest, EC_KEY* ec_key) {
	char *dgst = std_to_c_string(digest);
	unsigned int sig_len;
	unsigned char *signature;
	std::string result;

	if ((sig_len = ECDSA_size(ec_key)) == 0) {
		std::cerr << "Failed to get the size of the key" << std::endl;
		goto free_dgst;
	}

	if ((signature = (unsigned char *)OPENSSL_malloc(sig_len)) == NULL) {
		std::cerr << "Failed to malloc" << std::endl;
		goto free_dgst;
	}

	if (ECDSA_sign(0, reinterpret_cast<const unsigned char *>(dgst), digest.size(), signature, &sig_len, ec_key) == 0) {
		std::cerr << "Failed to sign" << std::endl;
		goto free_signature;
	}

	result = crypto::Base64Encode(std::string(reinterpret_cast<char *>(signature), sig_len));  // Success
	OPENSSL_free(signature);
	free(dgst);
	return result;

free_signature:
	OPENSSL_free(signature);
free_dgst:
	free(dgst);
	return "";
}

bool crypto::verifyWithECDSA(const std::string& digest, const std::string& b64_signature, EC_KEY* ec_key) {
	// Decode the signature from base64
	auto decoded = crypto::Base64Decode(b64_signature);
	char *decoded_sig = std_to_c_string(decoded);
	char *dgst = std_to_c_string(digest);

	bool result = ECDSA_verify(0, reinterpret_cast<const unsigned char *>(dgst), digest.size(), reinterpret_cast<const unsigned char *>(decoded_sig), decoded.size(), ec_key) == 1;
	free(decoded_sig);
	free(dgst);
	return result;
}

std::string crypto::getPublicKey(EC_KEY* ec_key) {
	const EC_POINT *ec_point; // No need to free
	EC_GROUP *ec_group;
	unsigned char *pubkey;
	size_t length;
	std::string result;

	if ((ec_point = EC_KEY_get0_public_key(ec_key)) == NULL) {
		std::cerr << "Failed to obtain public key" << std::endl;
		goto err_return;
	}

	ec_group = EC_GROUP_new_by_curve_name(NID_secp192k1);
	if (ec_group == NULL) {
		std::cerr << "Failed to create ec_group" << std::endl;
		goto err_return;
	}

	if ((length = EC_POINT_point2buf(ec_group, ec_point, POINT_CONVERSION_UNCOMPRESSED, &pubkey, NULL)) == 0) {
		std::cerr << "Failed to convert EC point to buffer" << std::endl;
		goto free_ec_group;
	}

	// Success
	result = crypto::SHA256(std::string(reinterpret_cast<char *>(pubkey), length));
	EC_GROUP_free(ec_group);
	OPENSSL_free(pubkey);
	return result;

free_ec_group:
	EC_GROUP_free(ec_group);
err_return:
	return "";
}

void crypto::freeECDSAPrivateKey(EC_KEY*ec_key) {
	EC_KEY_free(ec_key);
	ec_key = NULL;
}

std::string crypto::Base64Encode(const std::string& buffer) {
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64()); // Encode any data written to it to base64
	bio = BIO_new(BIO_s_mem()); // Source sink bio using memory for operations
	bio = BIO_push(b64, bio); // Pushes b64 on bio

	char *buf = std_to_c_string(buffer);
	BIO_write(bio, buf, buffer.size()); 
	BIO_flush(bio); 
  BIO_get_mem_ptr(bio, &bufferPtr);
  BIO_set_close(bio, BIO_NOCLOSE);

  BIO_free_all(bio);
	free(buf);

  return std::string((*bufferPtr).data);
}

std::string crypto::Base64Decode(const std::string& b64_input) {
	// Calculating the length of the b64 string
	int len = b64_input.size(), padding = 0;

	if (b64_input[len-1] == '=')
		padding++;
	if (b64_input[len-2] == '=')
		padding++;

	len = (len * 3) / 4 - padding;

	BIO *bio, *b64;
	unsigned char *buffer = (unsigned char*)malloc(len + 1);
  buffer[len] = '\0';

	char *input = std_to_c_string(b64_input);
  bio = BIO_new_mem_buf(input, -1);
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);
  int length = BIO_read(bio, buffer, b64_input.size());

  BIO_free_all(bio);
	free(input);

	auto result = std::string(reinterpret_cast<char *>(buffer), length);
	free(buffer);
	return result;
}