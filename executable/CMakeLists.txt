set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

add_executable(example main.cpp)

target_link_libraries(example aes kalyna gmpxx libgmp rsa)