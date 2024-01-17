// encryption_engine.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _EFC_ENCRYPTION_ENGINE_HPP_
#define _EFC_ENCRYPTION_ENGINE_HPP_
#include <efc/secure_buffer.hpp>
#include <mjstr/char_traits.hpp>

namespace mjx {
    using key                = secure_buffer<32>;
    using iv                 = secure_buffer<12>;
    using authentication_tag = secure_buffer<16>;

    iv generate_iv() noexcept;

    class encryption_engine { // default encryption engine
    public:
        encryption_engine() noexcept;
        ~encryption_engine() noexcept;

        encryption_engine(const encryption_engine&)            = delete;
        encryption_engine& operator=(const encryption_engine&) = delete;

        // setups the engine for encryption
        bool setup_encryption(const key& _Key, const iv& _Iv) noexcept;

        // setups the engine for decryption
        bool setup_decryption(const key& _Key, const iv& _Iv) noexcept;
    
        // encrypts a byte sequence
        bool encrypt(const byte_t* const _Bytes, const size_t _Count, byte_t* const _Buf) noexcept;

        // decrypts a byte sequence
        bool decrypt(const byte_t* const _Bytes, const size_t _Count, byte_t* const _Buf) noexcept;
    
        // completes encryption or decryption
        bool complete(authentication_tag& _Tag) noexcept;

    private:
        enum _Internal_state : unsigned char {
            _Uninitialized,
            _Initialized_for_encryption,
            _Initialized_for_decryption
        };
        
        // obtains the stored authentication tag
        bool _Get_tag(authentication_tag& _Tag) noexcept;

        // changes the stored authentication tag
        bool _Set_tag(authentication_tag& _Tag) noexcept;

        bool _Complete(authentication_tag& _Tag) noexcept;

        _Internal_state _Mystate;
        void* _Myctx;
    };
} // namespace mjx

#endif // _EFC_ENCRYPTION_ENGINE_HPP_