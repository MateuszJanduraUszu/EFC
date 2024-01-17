// secure_buffer.cpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <cstring>
#include <efc/impl/secure_memory.hpp>
#include <efc/impl/tinywin.hpp>
#include <efc/secure_buffer.hpp>
#include <type_traits>

namespace mjx {
    template <size_t _Size>
    secure_buffer<_Size>::secure_buffer() noexcept : _Mydata{0} {}

    template <size_t _Size>
    secure_buffer<_Size>::secure_buffer(const secure_buffer& _Other) noexcept : _Mydata{0} {
        efc_impl::_Copy_sensitive_data(_Mydata, _Other._Mydata, _Size);
    }

    template <size_t _Size>
    secure_buffer<_Size>::secure_buffer(secure_buffer&& _Other) noexcept : _Mydata{0} {
        efc_impl::_Move_sensitive_data(_Mydata, _Other._Mydata, _Size);
    }

    template <size_t _Size>
    secure_buffer<_Size>::~secure_buffer() noexcept {
        efc_impl::_Wipe_memory(_Mydata, _Size);
    }

    template <size_t _Size>
    secure_buffer<_Size>& secure_buffer<_Size>::operator=(const secure_buffer& _Other) noexcept {
        if (this != ::std::addressof(_Other)) {
            efc_impl::_Copy_sensitive_data(_Mydata, _Other._Mydata, _Size);
        }

        return *this;
    }

    template <size_t _Size>
    secure_buffer<_Size>& secure_buffer<_Size>::operator=(secure_buffer&& _Other) noexcept {
        if (this != ::std::addressof(_Other)) {
            efc_impl::_Move_sensitive_data(_Mydata, _Other._Mydata, _Size);
        }

        return *this;
    }

    template <size_t _Size>
    bool secure_buffer<_Size>::valid() const noexcept {
        byte_t _Zeros[_Size] = {0};
        return ::memcmp(_Mydata, _Zeros, _Size) != 0;
    }

    template <size_t _Size>
    byte_t* secure_buffer<_Size>::data() noexcept {
        return _Mydata;
    }

    template <size_t _Size>
    const byte_t* secure_buffer<_Size>::data() const noexcept {
        return _Mydata;
    }

    template <size_t _Size>
    void secure_buffer<_Size>::assign(const byte_t* const _Bytes) noexcept {
        // behavior is undefined if _Bytes's size is less than _Size
        ::memmove(_Mydata, _Bytes, _Size); // avoid memory overlapping
    }

    template <size_t _Size>
    void secure_buffer<_Size>::reset() noexcept {
        efc_impl::_Wipe_memory(_Mydata, _Size);
    }
} // namespace mjx