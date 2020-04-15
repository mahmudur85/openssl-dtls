cmake_minimum_required(VERSION 3.5)
project(libdtls-test)

set(CMAKE_CXX_STANDARD 11)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -Wall")

# enable debug level
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DDEBUG")

# enable this to use EPOLL event data pointer
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DWITH_EPOLL_DATA_PTR")

# enable non-blocking socket
# NOTE: DTLSv1_listen() misses dose not support non-blocking socket connection
#set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSOCK_NON_BLOCKING")

file(GLOB SRC_FILES src/*.cpp src/*.hpp src/*.c src/*.h)

include_directories(include)

add_executable(libdtls-test ${SRC_FILES})

target_link_libraries(libdtls-test pthread OpenSSL::SSL OpenSSL::Crypto ${CMAKE_DL_LIBS})