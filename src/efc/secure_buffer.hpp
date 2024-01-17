// secure_buffer.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _EFC_SECURE_BUFFER_HPP_
#define _EFC_SECURE_BUFFER_HPP_
#include <cstddef>
#include <mjstr/char_traits.hpp>

namespace mjx {
    template <size_t _Size>
    class secure_buffer { // stores memory block with secure memory semantics
    public:
        secure_buffer() noexcept;
        secure_buffer(const secure_buffer& _Other) noexcept;
        secure_buffer(secure_buffer&& _Other) noexcept;
        ~secure_buffer() noexcept;

        secure_buffer& operator=(const secure_buffer& _Other) noexcept;
        secure_buffer& operator=(secure_buffer&& _Other) noexcept;

        static constexpr size_t size = _Size;

        // checks if the stored data is valid
        bool valid() const noexcept;

        // returns the stored data
        byte_t* data() noexcept;
        const byte_t* data() const noexcept;

        // assigns a new data
        void assign(const byte_t* const _Bytes) noexcept;

        // erases the stored data
        void reset() noexcept;

    private:
        byte_t _Mydata[_Size];
    };

#pragma warning(push, 1)
#pragma warning(disable : 4661) // C4661: template-class method declared but not defined
    // these declarations enable the compilation of key, iv, authentication_tag and salt classes
    template class secure_buffer<32>;
    template class secure_buffer<16>;
    template class secure_buffer<12>;
#pragma warning(pop)
} // namespace mjx

#endif // _EFC_SECURE_BUFFER_HPP_