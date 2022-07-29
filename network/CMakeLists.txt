project (Network)

file(GLOB SRC_FILES ${PROJECT_SOURCE_DIR}/src/*.cpp)

add_library(${PROJECT_NAME} SHARED ${SRC_FILES})

find_path(LIBNET_INCLUDE_DIR libnet.h
	/usr/include
)

find_path(LIBPCAP_INCLUDE_DIR pcap.h
	/usr/include
)

find_library(LIBNET_LIBRARY 
	NAMES net libnet 
	PATHS /usr/lib /usr/local/lib
)

find_library(PCAP_LIBRARY
	NAMES pcap libpcap
	PATH /usr/lib /usr/local/lib
)

if (LIBNET_INCLUDE_DIR AND LIBNET_LIBRARY)
	MESSAGE(STATUS "LIBNET Found!")
	if (PCAP_LIBRARY AND LIBPCAP_INCLUDE_DIR)
		MESSAGE(STATUS "LIBPCAP Found!")
		target_link_libraries(${PROJECT_NAME} 
			PUBLIC ${LIBNET_LIBRARY} ${PCAP_LIBRARY}
		)
	else()
		MESSAGE(STATUS "LIBPCAP Not Found!")
	endif()
else()
	MESSAGE(STATUS "LIBNET Not Found!")
endif()

target_include_directories(${PROJECT_NAME}
	PUBLIC ${PROJECT_SOURCE_DIR}/include
	LIBNET_INCLUDE_DIR
	LIBPCAP_INCLUDE_DIR
)