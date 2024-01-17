// file_encryption_engine.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _EFC_IMPL_FILE_ENCRYPTION_ENGINE_HPP_
#define _EFC_IMPL_FILE_ENCRYPTION_ENGINE_HPP_
#include <efc/file_encryption_engine.hpp>

namespace mjx {
    namespace efc_impl {
        inline constexpr byte_t _Well_known_signature[file_signature::size] = {'E', 'F', 'C', '\0'};

        class _Metadata_parser {
        public:
            explicit _Metadata_parser(const byte_t* const _Raw) noexcept : _Myraw(_Raw) {}

            void _Parse(byte_t* const _Meta, const size_t _Size) noexcept {
                ::memcpy(_Meta, _Myraw, _Size);
                _Myraw += _Size;
            }

        private:
            const byte_t* _Myraw;
        };

        class _Metadata_serializer {
        public:
            explicit _Metadata_serializer(byte_t* const _Raw) noexcept : _Myraw(_Raw), _Myoff(0) {}

            void _Serialize(const byte_t* const _Meta, const size_t _Size) noexcept {
                ::memcpy(_Myraw, _Meta, _Size);
                _Myraw += _Size;
                _Myoff += _Size;
            }

            byte_t* _Begin() noexcept {
                _Myraw -= _Myoff; // go back to the beginning of the buffer
                return _Myraw;
            }

        private:
            byte_t* _Myraw;
            size_t _Myoff;
        };
    } // namespace efc_impl
} // namespace mjx

#endif // _EFC_IMPL_FILE_ENCRYPTION_ENGINE_HPP_