add_library(aes
        aes-helpers/tables.h
        aes-helpers/tables.cpp
        aes-helpers/transformations.h
        aes-helpers/transformations.cpp
        include/aes.h
        src/aes.cpp)

add_library(kalyna
        kalyna-helpers/tables.h
        kalyna-helpers/tables.cpp
        kalyna-helpers/transformations.h
        kalyna-helpers/transformations.cpp
        include/kalyna.h
        src/kalyna.cpp)

add_library(rc4
        include/rc4.h
        src/rc4.cpp)

add_library(salsa20
        include/salsa20.h
        src/salsa20.cpp)

add_library(sha256
        include/sha256.h
        src/sha256.cpp)

add_library(kupyna
        kupyna-helpers/tables.h
        kupyna-helpers/tables.cpp
        include/kupyna.h
        src/kupyna.cpp)

add_library(rsa
        rsa-helpers/rsa-helpers.h
        rsa-helpers/rsa-helpers.cpp
        rsa-helpers/OAE.h
        rsa-helpers/OAE.cpp
        include/rsa.h
        src/rsa.cpp)

target_include_directories(aes PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        PRIVATE src aes-helpers)

target_include_directories(kalyna PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        PRIVATE src kalyna-helpers)

target_include_directories(rc4 PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        PRIVATE src)

target_include_directories(salsa20 PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        PRIVATE src)

target_include_directories(sha256 PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        PRIVATE src)

target_include_directories(kupyna PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        PRIVATE src kupyna-helpers)

target_include_directories(rsa PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        PRIVATE src rsa-helpers)

set_target_properties(aes kalyna rc4 salsa20 sha256 kupyna rsa PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS OFF)