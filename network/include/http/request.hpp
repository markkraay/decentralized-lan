#pragma once

#include <nlohmann/json.hpp>

#include <string>

namespace http {
	// Outlines the anatomy of an HTTP request
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages

	struct request {
		enum class method {
			GET, 
			POST
		};

		method method;
		std::string path;
		nlohmann::json payload;

		inline std::string to_string() {
			std::string result = "";
			switch(this->method) {
				case method::GET:
					result += "GET ";
					break;
				case method::POST:
					result += "POST ";
					break;
			}
			result += "Path: " + path + "\nPayload: " + payload.dump() + '\n';
			return result;
		}
	};
}