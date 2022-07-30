cmake_minimum_required(VERSION 3.10)

project(LANCoin VERSION 1.0)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_subdirectory(network)

add_executable(${PROJECT_NAME} main.cpp)

target_link_libraries(LANCoin 
	PUBLIC Network
)