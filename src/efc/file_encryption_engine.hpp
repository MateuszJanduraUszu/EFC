// file_encryption_engine.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _EFC_FILE_ENCRYPTION_ENGINE_HPP_
#define _EFC_FILE_ENCRYPTION_ENGINE_HPP_
#include <efc/encryption_engine.hpp>
#include <efc/key_derivation.hpp>
#include <mjfs/file_stream.hpp>

namespace mjx {
    struct file_signature {
        static constexpr size_t size = 4;
        byte_t data[size]            = {0};

        // checks if the signature is well-known
        bool is_recognized() const noexcept;
    };

    struct file_metadata {
        file_signature signature;
        authentication_tag tag;
        salt salt;
        iv iv;
    };

    file_metadata construct_metadata() noexcept;
    file_metadata load_metadata(file_stream& _Stream) noexcept;
    bool store_metadata(file_stream& _Stream, const file_metadata& _Meta) noexcept;

    class file_encryption_engine {
    public:
        file_encryption_engine(
            file_stream& _Src_stream, file_stream& _Dest_stream, encryption_engine& _Engine) noexcept;
        ~file_encryption_engine() noexcept;

        file_encryption_engine(const file_encryption_engine&)            = delete;
        file_encryption_engine& operator=(const file_encryption_engine&) = delete;

        // encrypts the file
        bool encrypt(const key& _Key, const iv& _Iv, authentication_tag& _Tag) noexcept;

        // decrypts the file
        bool decrypt(const key& _Key, const iv& _Iv, authentication_tag& _Tag) noexcept;

    private:
        file_stream& _Mysrc;
        file_stream& _Mydest;
        encryption_engine& _Myengine;
    };
} // namespace mjx

#endif // _EFC_FILE_ENCRYPTION_ENGINE_HPP_