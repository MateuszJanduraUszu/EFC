// program.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _EFC_PROGRAM_HPP_
#define _EFC_PROGRAM_HPP_
#include <efc/encryption_engine.hpp>
#include <efc/key_derivation.hpp>
#include <mjfs/path.hpp>

namespace mjx {
    enum class operation : unsigned char {
        none,
        help,
        encryption,
        decryption
    };

    struct program_options {
        path path_to_file;
        operation operation;
        secure_password password;

        program_options() noexcept;
    };

    void parse_program_args(int _Count, wchar_t** _Args, program_options& _Options);
} // namespace mjx

#endif // _EFC_PROGRAM_HPP_