#pragma once

#include <nlohmann/json.hpp>

#include <string>

using json = nlohmann::json;

namespace http {
	typedef struct {
		struct status_line {
			int code;
			std::string reason_phrase;

			inline std::string to_string() {
				return "HTTP/1.1 " + std::to_string(code) + " " + reason_phrase;
			}
		};

		struct header {
			std::string content_type;
			int content_length;

			inline std::string to_string() {
				return "Content-Type: " + content_type + "\r\nContent-Length: " + std::to_string(content_length);
			}
		};

		struct status_line status_line;
		struct header header;
		std::string body;

		inline std::string to_string() {
			return status_line.to_string() + "\r\n" + header.to_string() + "\r\n\r\n" + body;
		}
	} response;

	http::response response_200(std::string body) {
		return http::response {
			{200, "OK"},
			{"application/json", (int)body.size() + 2},
			body + "\r\n"
		};
	}

	http::response response_401(std::string body) {
		return http::response {
			{401, "Unauthorized Request"},
			{"html/text", (int)body.size() + 2},
			body + "\r\n"
		};
	}

	http::response response_404(std::string body) {
		return http::response {
			{404, "Page Not Found"},
			{"html/text", (int)body.size() + 2},
			body + "\r\n"
		};
	}

	http::response response_500(std::string body) {
		return http::response {
			{500, "Internal Server Error"},
			{"html/text", (int)body.size() + 2},
			body + "\r\n"
		};
	}

	http::response invalid_request_response = response_404("Invalid Request");
	http::response invalid_path_response = response_404("Invalid Path");
	http::response unauthorized_request_response = response_401("You do not have permission to access this endpoint");
};