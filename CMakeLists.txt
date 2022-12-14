cmake_minimum_required(VERSION 3.10)

project(LANCoin VERSION 1.0)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	set(MACOS TRUE)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	set(LINUX TRUE)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
	set(WINDOWS TRUE)
endif()

if(MACOS) 
	set(OPENSSL_ROOT_DIR "/usr/local/Cellar/openssl@3/3.0.5")
	include_directories(${PROJECT_NAME} PUBLIC 
		"/usr/local/include"
		"/usr/local/Cellar/openssl@3/3.0.5/include"
	)
endif()

add_subdirectory(crypt)
add_subdirectory(blockchain)
add_subdirectory(network)
add_subdirectory(node)

add_executable(${PROJECT_NAME} main.cpp)

target_link_libraries(LANCoin 
	PUBLIC Crypt Blockchain Network Node
)

