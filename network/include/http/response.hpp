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

	http::response invalid_path_response {
		{404, "Page Not Found"},
		{"html/text", 15},
		"Invalid Path\r\n"
	};

	http::response invalid_request_response {
		{404, "Page Not Found"},
		{"html/text", 18},
		"Invalid Request\r\n"
	};

	http::response unauthorized_request_response {
		{401, "Unauthorized Request"},
		{"html/text", 52},
		"You do not have permission to access this endpoint\r\n"
	};

	http::response ok_response(std::string body) {
		return http::response {
			{200, "OK"},
			{"application/json", (int)body.size() + 2},
			body + "\r\n"
		};
	}
};