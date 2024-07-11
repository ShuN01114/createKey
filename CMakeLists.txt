# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.13)

project(generateKeys VERSION 4.0.0 LANGUAGES CXX)

# If not called from root CMakeLists.txt
if(NOT DEFINED SEAL_BUILD_EXAMPLES)
    set(SEAL_BUILD_EXAMPLES ON)

    # Import Microsoft SEAL
    find_package(SEAL 4.0.0 EXACT REQUIRED)

    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
endif()

if(SEAL_BUILD_EXAMPLES)
    add_executable(generateKeys)

    target_sources(generateKeys
        PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/genkey.cpp
    )

    if(TARGET SEAL::seal)
        target_link_libraries(generateKeys PRIVATE SEAL::seal)
        # target_link_libraries(myadd PRIVATE SEAL::seal)
    elseif(TARGET SEAL::seal_shared)
        target_link_libraries(generateKeys PRIVATE SEAL::seal_shared)
        # target_link_libraries(myadd PRIVATE SEAL::seal_shared)
    else()
        message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
    endif()
endif()
