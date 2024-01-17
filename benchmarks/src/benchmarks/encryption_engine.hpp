// encryption_engine.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _EFC_BENCH_BENCHMARKS_ENCRYPTION_ENGINE_HPP_
#define _EFC_BENCH_BENCHMARKS_ENCRYPTION_ENGINE_HPP_
#include <benchmark/benchmark.h>
#include <efc/encryption_engine.hpp>

namespace mjx {
    namespace bench {
        template <class _Ty>
        inline secure_buffer<_Ty::size> _Assign_bytes(const char* const _Bytes) noexcept {
            secure_buffer<_Ty::size> _Buf;
            _Buf.assign(reinterpret_cast<const byte_t*>(_Bytes));
            return _Buf;
        }

        authentication_tag _Tag; // automatically assigned
        const key& _Key             = _Assign_bytes<key>("\x3E\x2F\x7A\xA1\xB2\xC3\xD4\xE5\xF6\x07\x18\x29"
                                                         "\x3A\x4B\x5C\x6D\x8F\x90\xA1\xB2\xC3\xD4\xE5\xF6"
                                                         "\x07\x18\x29\x3A\x4B\x5C\x6D\x7E");
        const iv& _Iv               = _Assign_bytes<iv>("\xA1\xB2\xC3\xD4\xE5\xF6\x07\x18\x29\x3A\x4B\x5C");
        const char* const _Dec_text = "\xA1\xB2\xC3\xD4\xE5\xF6\x07\x18\x29\x3A\x4B\x5C\x6D\x7E\x8F\x90"
                                      "\x3A\x4B\x5C\x6D\x7E\x8F\x90\xA1\xB2\xC3\xD4\xE5\xF6\x07\x18\x29"
                                      "\xA1\xB2\xC3\xD4\xE5\xF6\x07\x18\x29\x3A\x4B\x5C\x6D\x7E\x8F\x90"
                                      "\xA1\xB2\xC3\xD4\xE5\xF6\x07\x18\x29\x3A\x4B\x5C\x6D\x7E\x8F\x90"
                                      "\xA1\xB2\xC3\xD4\xE5\xF6\x07\x18\x29\x3A\x4B\x5C\x6D\x7E\x8F\x90"
                                      "\xA1\xB2\xC3\xD4\xE5\xF6\x07\x18\x29\x3A\x4B\x5C\x6D\x7E\x8F\x90"
                                      "\xA1\xB2\xC3\xD4\xE5\xF6\x5C\x6D\x7E\x8F\x90\xA1\xB2\xC3\xD4\xE5"
                                      "\xF6\x07\x18\x29\x3A\x4B\x5C\x7E\x8F\x90\xA1\xB2\xC3\xD4\xE5\xF6";
        const char* const _Enc_text = "\x9C\x81\xE3\x98\xD9\x66\xA0\xD3\xDC\xEC\xBD\x56\x3F\x44\xF8\x97"
                                      "\xA0\xD9\x60\xC2\x24\x9F\xE0\x14\x86\x91\x1F\xA2\x3A\xE2\x7F\x34"
                                      "\x5A\x7D\x92\x0A\xA5\x49\x77\xEB\x37\x65\x8A\xE2\xC4\x95\x05\x58"
                                      "\x90\x04\xFA\xC5\x57\x30\x52\x21\xAB\x37\xE0\x6D\xF4\xE0\x9E\x25"
                                      "\x3C\xCB\x2B\x90\xC3\xDB\x71\x2B\xE7\x7E\x05\x6F\x61\x75\x3E\x08"
                                      "\x0D\x73\xBF\x6A\x39\x99\x80\x9E\xB4\x89\x40\x9F\xDB\x11\xF6\xF1"
                                      "\xFE\xF8\xF6\x98\x72\x80\x2C\x39\x4F\xB4\xE1\x95\xF8\xE2\xEC\x70"
                                      "\xDB\x6A\xF7\x85\xA7\x3F\xE4\x15\xEB\x48\x37\xE5\x85\x83\x05\xEF";
        constexpr size_t _Text_size = 128;

        inline bool encrypt() noexcept {
            encryption_engine _Engine;
            byte_t _Buf[_Text_size]; // fits encrypted _Dec_buf
            return _Engine.setup_encryption(_Key, _Iv) && _Engine.encrypt(reinterpret_cast<const byte_t*>(
                _Dec_text), _Text_size, _Buf) && _Engine.complete(_Tag);
        }

        inline bool decrypt() noexcept {
            encryption_engine _Engine;
            byte_t _Buf[_Text_size]; // fits decrypted _Enc_buf
            return _Engine.setup_decryption(_Key, _Iv) && _Engine.decrypt(reinterpret_cast<const byte_t*>(
                _Enc_text), _Text_size, _Buf) && _Engine.complete(_Tag);
        }

        void bm_encrypt(::benchmark::State& _State) {
            for (const auto& _Step : _State) {
                ::benchmark::DoNotOptimize(encrypt());
            }
        }

        void bm_decrypt(::benchmark::State& _State) {
            for (const auto& _Step : _State) {
                ::benchmark::DoNotOptimize(decrypt());
            }
        }

        BENCHMARK(bm_encrypt)->DenseRange(0, 10)->Unit(::benchmark::TimeUnit::kNanosecond);
        BENCHMARK(bm_decrypt)->DenseRange(0, 10)->Unit(::benchmark::TimeUnit::kNanosecond);
    } // namespace bench
} // namespace mjx

#endif // _EFC_BENCH_BENCHMARKS_ENCRYPTION_ENGINE_HPP_