// program.hpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once
#ifndef _EFC_IMPL_PROGRAM_HPP_
#define _EFC_IMPL_PROGRAM_HPP_
#include <efc/program.hpp>
#include <mjfs/status.hpp>
#include <type_traits>

namespace mjx {
    namespace efc_impl {
        struct _Parser_context{
            bool _Path_found      : 3;
            bool _Operation_found : 3;
            bool _Password_found  : 2;

            _Parser_context() noexcept : _Path_found(false), _Operation_found(false), _Password_found(false) {}

            bool _Parse_completed() const noexcept {
                return _Path_found && _Operation_found && _Password_found;
            }
        };

        struct _Parser_data {
            unicode_string_view _Arg;
            program_options& _Options;

            explicit _Parser_data(program_options& _Options) noexcept : _Arg(), _Options(_Options) {}
        };

        inline bool _Parse_path(_Parser_context& _Ctx, _Parser_data& _Data) {
            if (!_Data._Arg.starts_with(L"--path=")) {
                return false;
            }

            path _Path = _Data._Arg.substr(_Data._Arg.find(L'=') + 1);
            if (!::mjx::exists(_Path)) {
                return false;
            }

            _Data._Options.path_to_file = ::std::move(_Path);
            _Ctx._Path_found            = true;
            return true;
        }

        inline bool _Parse_operation(_Parser_context& _Ctx, _Parser_data& _Data) noexcept {
            if (_Data._Arg == L"--help") {
                _Data._Options.operation = operation::help;
            } else if (_Data._Arg == L"--encrypt") {
                _Data._Options.operation = operation::encryption;
            } else if (_Data._Arg == L"--decrypt") {
                _Data._Options.operation = operation::decryption;
            } else {
                return false;
            }

            _Ctx._Operation_found = true;
            return true;
        }

        inline bool _Parse_password(_Parser_context& _Ctx, _Parser_data& _Data) noexcept {
            if (!_Data._Arg.starts_with(L"--password=")) {
                return false;
            }

            _Data._Options.password.assign(_Data._Arg.substr(_Data._Arg.find(L'=') + 1));
            _Ctx._Password_found = true;
            return true;
        }
    } // namespace efc_impl
} // namespace mjx

#endif // _EFC_IMPL_PROGRAM_HPP_