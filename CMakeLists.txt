cmake_minimum_required(VERSION 3.3)
project(mini_malloc)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -Og -Wall -Wextra -pedantic -Werror")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-error=unused-parameter")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-error=sign-compare")

add_library(mini_malloc mini_malloc.c mini_malloc.h)
target_link_libraries(mini_malloc m)
