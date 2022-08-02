project (Network)

file(GLOB SRC_FILES ${PROJECT_SOURCE_DIR}/src/*.cpp)

add_library(${PROJECT_NAME} SHARED ${SRC_FILES})

find_path(PCAP_INCLUDE_DIR pcap.h
	/usr/include # Linux
	/usr/local/include # MacOS
)

find_library(PCAP_LIBRARY
	NAMES pcap libpcap
	PATH 
	/usr/lib /usr/local/lib # Linux + MacOS
)

if (NOT PCAP_INCLUDE_DIR)
	message(FATAL_ERROR "Could not find libpcap library")
elseif (NOT PCAP_LIBRARY) 
	message(FATAL_ERROR "Could not find libpcap header files")
else()
	message(STATUS "Found libpcap")
endif()

target_link_libraries(${PROJECT_NAME} 
	PUBLIC ${PCAP_LIBRARY} Crypt Blockchain
)

target_include_directories(${PROJECT_NAME}
	PUBLIC ${PROJECT_SOURCE_DIR}/include
	${LIBNET_INCLUDE_DIR}
	${LIBPCAP_INCLUDE_DIR}
)