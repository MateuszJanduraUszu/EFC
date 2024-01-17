// random.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _EFC_IMPL_RANDOM_HPP_
#define _EFC_IMPL_RANDOM_HPP_
#include <mjstr/char_traits.hpp>
#include <openssl/rand.h>

namespace mjx {
    namespace efc_impl {
        inline bool _Random_bytes(byte_t* const _Buf, const size_t _Size) noexcept {
            return ::RAND_bytes(_Buf, static_cast<int>(_Size)) != 0;
        }
    } // namespace efc_impl
} // namespace mjx

#endif // _EFC_IMPL_RANDOM_HPP_