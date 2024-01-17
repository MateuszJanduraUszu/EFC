# CMakeLists.txt

# Copyright (c) Mateusz Jandura. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.21)
project(efc
    VERSION 1.0.0
    DESCRIPTION "EFC (Easy File Crypt)"
    LANGUAGES CXX
)

set(CXX_STANDARD 17)
set(CXX_STANDARD_REQUIRED ON)

# translate x64/Win32 into x64/x86
if(CMAKE_GENERATOR_PLATFORM STREQUAL x64)
    set(EFC_PLATFORM_ARCH x64)
elseif(CMAKE_GENERATOR_PLATFORM STREQUAL Win32)
    set(EFC_PLATFORM_ARCH x86)
else()
    set(EFC_PLATFORM_ARCH Invalid)
    message(FATAL_ERROR "Requires either x64 or Win32 platform architecture.")
endif()

set(CMAKE_SUPPRESS_REGENERATION TRUE)
if(MSVC)
    set(VS_SOURCE_GROUPS src)
endif()

set(EFC_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src")
set(EFC_SOURCES
    "${EFC_SRC_DIR}/efc/encryption_engine.cpp"
    "${EFC_SRC_DIR}/efc/encryption_engine.hpp"
    "${EFC_SRC_DIR}/efc/file_encryption_engine.cpp"
    "${EFC_SRC_DIR}/efc/file_encryption_engine.hpp"
    "${EFC_SRC_DIR}/efc/key_derivation.cpp"
    "${EFC_SRC_DIR}/efc/key_derivation.hpp"
    "${EFC_SRC_DIR}/efc/main.cpp"
    "${EFC_SRC_DIR}/efc/program.cpp"
    "${EFC_SRC_DIR}/efc/program.hpp"
    "${EFC_SRC_DIR}/efc/secure_buffer.cpp"
    "${EFC_SRC_DIR}/efc/secure_buffer.hpp"
)
set(EFC_IMPL_SOURCES
    "${EFC_SRC_DIR}/efc/impl/file_encryption_engine.hpp"
    "${EFC_SRC_DIR}/efc/impl/program.hpp"
    "${EFC_SRC_DIR}/efc/impl/random.hpp"
    "${EFC_SRC_DIR}/efc/impl/secure_memory.hpp"
    "${EFC_SRC_DIR}/efc/impl/tinywin.hpp"
)

# put all source files in "src" and "src\impl" directory
source_group("src" FILES ${EFC_SOURCES})
source_group("src/impl" FILES ${EFC_IMPL_SOURCES})

# put the compiled executable in either "bin\Debug" or "bin\Release" directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/${CMAKE_BUILD_TYPE}")

add_executable(efc ${EFC_SOURCES} ${EFC_IMPL_SOURCES})

target_compile_features(efc PRIVATE cxx_std_17)
target_include_directories(efc PRIVATE
    "${EFC_SRC_DIR}"
    "${EFC_SRC_DIR}/thirdparty/Botan/inc/${EFC_PLATFORM_ARCH}"
    "${EFC_SRC_DIR}/thirdparty/MJFS/inc/"
    "${EFC_SRC_DIR}/thirdparty/MJMEM/inc/"
    "${EFC_SRC_DIR}/thirdparty/MJSTR/inc/"
    "${EFC_SRC_DIR}/thirdparty/OpenSSL/inc/"
)
target_link_libraries(efc PRIVATE
    # link Botan
    $<$<CONFIG:Debug>:${EFC_SRC_DIR}/thirdparty/Botan/bin/${EFC_PLATFORM_ARCH}/Debug/botan.lib>
    $<$<CONFIG:Release>:${EFC_SRC_DIR}/thirdparty/Botan/bin/${EFC_PLATFORM_ARCH}/Release/botan.lib>

    # link MJFS module
    $<$<CONFIG:Debug>:${EFC_SRC_DIR}/thirdparty/MJFS/bin/${EFC_PLATFORM_ARCH}/Debug/mjfs.lib>
    $<$<CONFIG:Release>:${EFC_SRC_DIR}/thirdparty/MJFS/bin/${EFC_PLATFORM_ARCH}/Release/mjfs.lib>

    # link MJMEM module
    $<$<CONFIG:Debug>:${EFC_SRC_DIR}/thirdparty/MJMEM/bin/${EFC_PLATFORM_ARCH}/Debug/mjmem.lib>
    $<$<CONFIG:Release>:${EFC_SRC_DIR}/thirdparty/MJMEM/bin/${EFC_PLATFORM_ARCH}/Release/mjmem.lib>

    # link MJSTR module
    $<$<CONFIG:Debug>:${EFC_SRC_DIR}/thirdparty/MJSTR/bin/${EFC_PLATFORM_ARCH}/Debug/mjstr.lib>
    $<$<CONFIG:Release>:${EFC_SRC_DIR}/thirdparty/MJSTR/bin/${EFC_PLATFORM_ARCH}/Release/mjstr.lib>

    # link OpenSSL
    $<$<CONFIG:Debug>:${EFC_SRC_DIR}/thirdparty/OpenSSL/bin/${EFC_PLATFORM_ARCH}/Debug/libcrypto.lib>
    $<$<CONFIG:Release>:${EFC_SRC_DIR}/thirdparty/OpenSSL/bin/${EFC_PLATFORM_ARCH}/Release/libcrypto.lib>
)