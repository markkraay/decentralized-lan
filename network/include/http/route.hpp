#pragma once

#include "request.hpp"

#include <functional>
#include <string>

typedef struct {
	std::string path;
	std::function<std::string(http::request)> handle;
} Route;