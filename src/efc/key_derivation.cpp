// key_derivation.cpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <botan/argon2.h>
#include <cwchar>
#include <efc/impl/random.hpp>
#include <efc/impl/secure_memory.hpp>
#include <efc/key_derivation.hpp>
#include <mjstr/conversion.hpp>
#include <type_traits>
#include <utility>

namespace mjx {
    salt generate_salt() noexcept {
        salt _Salt;
        return efc_impl::_Random_bytes(_Salt.data(), salt::size) ? _Salt : salt{};
    }

    key derive_key(const unicode_string_view _Password, const salt& _Salt) noexcept {
        static constexpr uint8_t _Variant      = 2; // Argon2 variant (Argon2id)
        static constexpr size_t _Parallelism   = 1; // number of threads
        static constexpr size_t _Memory_amount = 16384; // memory amount in Kb
        static constexpr size_t _Iterations    = 8; // number of iterations
        const utf8_string& _Utf8_password      = ::mjx::to_utf8_string(_Password);
        key _Key;
        try {
            ::Botan::argon2(_Key.data(), key::size, _Utf8_password.c_str(), _Utf8_password.size(), _Salt.data(),
                salt::size, nullptr, 0, nullptr, 0, _Variant, _Parallelism, _Memory_amount, _Iterations);
            return _Key;
        } catch (...) {
            return key{};
        }
    }

    secure_password::secure_password() noexcept : _Mydata{0}, _Mylen(0) {}

    secure_password::secure_password(const secure_password& _Other) noexcept : _Mydata{0}, _Mylen(_Other._Mylen) {
        efc_impl::_Copy_sensitive_data(_Mydata, _Other._Mydata, _Mylen + 1);
    }

    secure_password::secure_password(secure_password&& _Other) noexcept : _Mydata{0}, _Mylen(_Other._Mylen) {
        efc_impl::_Move_sensitive_data(_Mydata, _Other._Mydata, _Mylen + 1);
        _Other._Mylen = 0;
    }

    secure_password::~secure_password() noexcept {
        efc_impl::_Wipe_memory(_Mydata, max_length + 1);
    }

    secure_password& secure_password::operator=(const secure_password& _Other) noexcept {
        if (this != ::std::addressof(_Other)) {
            efc_impl::_Copy_sensitive_data(_Mydata, _Other._Mydata, _Other._Mylen + 1);
            _Mylen = _Other._Mylen;
        }

        return *this;
    }

    secure_password& secure_password::operator=(secure_password&& _Other) noexcept {
        if (this != ::std::addressof(_Other)) {
            efc_impl::_Move_sensitive_data(_Mydata, _Other._Mydata, _Other._Mylen + 1);
            _Mylen        = _Other._Mylen;
            _Other._Mylen = 0;
        }

        return *this;
    }

    size_t secure_password::length() const noexcept {
        return _Mylen;
    }

    bool secure_password::empty() const noexcept {
        return _Mylen == 0;
    }

    wchar_t* secure_password::data() noexcept {
        return _Mydata;
    }

    const wchar_t* secure_password::data() const noexcept {
        return _Mydata;
    }

    unicode_string_view secure_password::as_view() const noexcept {
        return unicode_string_view{_Mydata, _Mylen};
    }

    void secure_password::assign(const unicode_string_view _New_password) noexcept {
        const size_t _Length = (::std::min)(_New_password.size(), max_length);
        ::wmemcpy(_Mydata, _New_password.data(), _Length);
        _Mylen = _Length;
    }
} // namespace mjx