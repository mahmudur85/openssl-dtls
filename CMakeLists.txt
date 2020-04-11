cmake_minimum_required(VERSION 3.5)
project(libdtls-test)

set(CMAKE_CXX_STANDARD 11)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -Wall")

# enable debug level
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DDEBUG")

file(GLOB SRC_FILES src/*.cpp src/*.hpp src/*.c src/*.h)

include_directories(include)

add_executable(libdtls-test ${SRC_FILES})

target_link_libraries(libdtls-test pthread OpenSSL::SSL OpenSSL::Crypto ${CMAKE_DL_LIBS})