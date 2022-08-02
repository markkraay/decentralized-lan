#pragma once

#include <string>

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
				return "Content-Type: " + content_type + "\nContent-Length: " + std::to_string(content_length);
			}
		};

		struct status_line status_line;
		struct header header;
		std::string body;

		inline std::string to_string() {
			return status_line.to_string() + "\n" + header.to_string() + "\n\n" + body + '\n';
		}
	} response;

	http::response invalid_path_response {
		{404, "Page Not Found"},
		{"html/text", 13},
		"Invalid Path"
	};

	http::response invalid_request_response {
		{404, "Page Not Found"},
		{"html/text", 16},
		"Invalid Request"
	};
};