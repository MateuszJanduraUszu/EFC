// secure_memory.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _EFC_IMPL_SECURE_MEMORY_HPP_
#define _EFC_IMPL_SECURE_MEMORY_HPP_
#include <cstddef>
#include <cstring>
#include <efc/impl/tinywin.hpp>

namespace mjx {
    namespace efc_impl {
        inline void _Wipe_memory(void* const _Ptr, const size_t _Size) noexcept {
            ::RtlSecureZeroMemory(_Ptr, _Size);
        }

        inline void _Copy_sensitive_data(void* const _Dest, const void* const _Src, const size_t _Size) noexcept {
            ::memcpy(_Dest, _Src, _Size);
        }

        inline void _Move_sensitive_data(void* const _Dest, void* const _Src, const size_t _Size) noexcept {
            ::memcpy(_Dest, _Src, _Size);
            _Wipe_memory(_Src, _Size);
        }
    } // namespace efc_impl
} // namespace mjx

#endif // _EFC_IMPL_SECURE_MEMORY_HPP_