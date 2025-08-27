cmake_minimum_required(VERSION 3.10)

project(tcp_example)

add_executable(server server.cpp)
add_executable(client client.cpp)

target_link_libraries(server ssl crypto)
target_link_libraries(client ssl crypto)
