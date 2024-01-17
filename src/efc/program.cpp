// program.cpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <efc/impl/program.hpp>
#include <efc/impl/secure_memory.hpp>
#include <efc/program.hpp>

namespace mjx {
    program_options::program_options() noexcept : path_to_file(), operation(operation::none), password() {}

    void parse_program_args(int _Count, wchar_t** _Args, program_options& _Options) {
        efc_impl::_Parser_context _Ctx;
        efc_impl::_Parser_data _Data(_Options);
        for (; _Count > 0 && !_Ctx._Parse_completed(); --_Count, ++_Args) {
            _Data._Arg = *_Args;
            if (!_Ctx._Path_found) { // search for a path
                if (efc_impl::_Parse_path(_Ctx, _Data)) {
                    continue;
                }
            }
            
            if (!_Ctx._Operation_found) { // search for an operation
                if (efc_impl::_Parse_operation(_Ctx, _Data)) {
                    continue;
                }
            }
            
            if (!_Ctx._Password_found) { // search for a password
                efc_impl::_Parse_password(_Ctx, _Data);
            }
        }
    }
} // namespace mjx