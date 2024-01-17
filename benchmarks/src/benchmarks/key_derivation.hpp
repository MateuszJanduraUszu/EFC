// key_derivation.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _EFC_BENCH_BENCHMARKS_KEY_DERIVATION_HPP_
#define _EFC_BENCH_BENCHMARKS_KEY_DERIVATION_HPP_
#include <benchmark/benchmark.h>
#include <efc/key_derivation.hpp>

namespace mjx {
    namespace bench {
        const salt& _Salt = generate_salt();

        void bm_derive_key(::benchmark::State& _State) {
            for (const auto& _Step : _State) {
                ::benchmark::DoNotOptimize(derive_key(L"ZD43MB$q|.iyUg4A", _Salt));
            }
        }

        BENCHMARK(bm_derive_key)->DenseRange(0, 10)->Unit(::benchmark::TimeUnit::kMillisecond);
    } // namespace bench
} // namespace mjx

#endif // _EFC_BENCH_BENCHMARKS_KEY_DERIVATION_HPP_