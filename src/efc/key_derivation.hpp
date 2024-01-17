// key_derivation.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _EFC_KEY_DERIVATION_HPP_
#define _EFC_KEY_DERIVATION_HPP_
#include <efc/encryption_engine.hpp>
#include <efc/secure_buffer.hpp>
#include <mjstr/string_view.hpp>

namespace mjx {
    using salt = secure_buffer<16>;

    salt generate_salt() noexcept;
    key derive_key(const unicode_string_view _Password, const salt& _Salt) noexcept;

    class secure_password { // stores fixed-size Unicode string with secure memory semantics
    public:
        secure_password() noexcept;
        secure_password(const secure_password& _Other) noexcept;
        secure_password(secure_password&& _Other) noexcept;
        ~secure_password() noexcept;

        secure_password& operator=(const secure_password& _Other) noexcept;
        secure_password& operator=(secure_password&& _Other) noexcept;

        static constexpr size_t max_length = 63;

        // returns the password length
        size_t length() const noexcept;

        // checks if the password is empty
        bool empty() const noexcept;

        // returns the stored data
        wchar_t* data() noexcept;
        const wchar_t* data() const noexcept;

        // returns the stored data as a string view
        unicode_string_view as_view() const noexcept;

        // assigns a new password
        void assign(const unicode_string_view _New_password) noexcept;

    private:
        wchar_t _Mydata[max_length + 1];
        size_t _Mylen;
    };
} // namespace mjx

#endif // _EFC_KEY_DERIVATION_HPP_