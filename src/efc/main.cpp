// main.cpp

// Copyright (c) Mateusz Jandura. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <cstdio>
#include <efc/file_encryption_engine.hpp>
#include <efc/program.hpp>
#include <mjfs/status.hpp>
#include <mjfs/temporary_file.hpp>

namespace mjx {
    enum class _App_error : unsigned char {
        _Success,
        _Operation_not_specified,
        _Password_not_specified,
        _Path_not_specified,
        _Signature_not_recognized,
        _Key_derivation_failed,
        _File_already_exists,
        _Invalid_file,
        _File_creation_failed,
        _Metadata_load_failed,
        _Metadata_store_failed,
        _Encryption_failed,
        _Decryption_failed,
        _Unknown_error
    };

    inline const char* _Translate_app_error(const _App_error _Error) noexcept {
        switch (_Error) {
        case _App_error::_Operation_not_specified:
            return "No operation specified.";
        case _App_error::_Password_not_specified:
            return "No password specified.";
        case _App_error::_Path_not_specified:
            return "File path not specified.";
        case _App_error::_Signature_not_recognized:
            return "Signature not recognized.";
        case _App_error::_Key_derivation_failed:
            return "Failed to derive the key.";
        case _App_error::_File_already_exists:
            return "Failed to create the file because it already exists.";
        case _App_error::_Invalid_file:
            return "Failed to open the file.";
        case _App_error::_File_creation_failed:
            return "Failed to create the file.";
        case _App_error::_Metadata_load_failed:
            return "Failed to load the metadata.";
        case _App_error::_Metadata_store_failed:
            return "Failed to store the metadata.";
        case _App_error::_Encryption_failed:
            return "Failed to encrypt the file.";
        case _App_error::_Decryption_failed:
            return "Failed to decrypt the file.";
        default:
            return "An unknown error occured.";
        }
    }

    inline void _Report_error(const _App_error _Error) noexcept {
        ::printf("[ERROR]: %s\n", _Translate_app_error(_Error));
    }

    inline path _Add_internal_extension(const path& _Path) {
        return path{_Path.native() + L".efc"};
    }

    inline path _Remove_internal_extension(const path& _Path) {
        const path::string_type& _Str = _Path.native();
        return path{_Str.substr(0, _Str.size() - 4)}; // assumes that _Path ends with ".efc"
    }

    inline void _Show_help() noexcept {
        ::puts(
            "EFC (Easy File Crypt) usage:\n"
            "\n"
            "efc.exe <operation> --path=\"<absolute-path>\" --password=\"<password>\"\n"
            "\n"
            "Operations:\n"
            "  --help       Show this help message end exit\n"
            "  --encrypt    Encrypt the specified file using the specified password\n"
            "  --decrypt    Decrypt the specified file using the specified password\n"
            "\n"
            "Notes:\n"
            "  When you encrypt the file, the program automatically creates a new file\n"
            "  called <absolute-path>.efc. If there is already a file with this name, an error occurs.\n"
            "\n"
            "  When you decrypt the file, the program expects that the file ends with .EFC extension,\n"
            "  otherwise an error occurs. The program automatically creates a new file named as\n"
            "  the file but without .EFC extension. If such file already exists, an error occurs.\n"
            "\n"
            "  All required data is stored within the file metadata, except for the password, which is required.\n"
            "  You can specify any password that is at most 63 characters long.\n"
            "\n"
            "Examples:\n"
            "  efc.exe --encrypt --path=\"C:\\Users\\Dir\\File.txt\" --password=\"My password\"\n"
            "  efc.exe --decrypt --path=\"C:\\Users\\Dir\\File.txt.efc\" --password=\"My password\"\n"
        );
    }

    inline _App_error _Perform_encryption(program_options& _Options) {
        const path& _Dest_path = _Add_internal_extension(_Options.path_to_file);
        if (::mjx::exists(_Dest_path)) { // must not exists
            return _App_error::_File_already_exists;
        }

        // Note: The newly created file is initially set as temporary to handle potential issues.
        //       Upon successful operation, it will be converted to a regular file.
        temporary_file _Dest_file;
        if (!::mjx::create_temporary_file(_Dest_path, _Dest_file)) {
            return _App_error::_File_creation_failed;
        }
        
        file _Src_file(_Options.path_to_file, file_access::read, file_share::read);
        file_stream _Src_stream(_Src_file);
        file_stream _Dest_stream(_Dest_file);
        if (!_Src_stream.is_open() || !_Dest_stream.is_open()) { // both streams must be valid
            return _App_error::_Invalid_file;
        }

        file_metadata _Meta = construct_metadata();
        const key& _Key     = derive_key(_Options.password.as_view(), _Meta.salt);
        if (!_Key.valid()) {
            return _App_error::_Key_derivation_failed;
        }

        if (!_Dest_stream.seek(sizeof(file_metadata))) { // leave space for the meta-data
            return _App_error::_Metadata_store_failed;
        }

        encryption_engine _EEng;
        file_encryption_engine _FEng(_Src_stream, _Dest_stream, _EEng);
        if (!_FEng.encrypt(_Key, _Meta.iv, _Meta.tag)) {
            return _App_error::_Encryption_failed;
        }

        if (!_Dest_stream.seek(0) || !store_metadata(_Dest_stream, _Meta)) {
            return _App_error::_Metadata_store_failed;
        }
        
        return _Dest_file.make_regular() ? _App_error::_Success : _App_error::_File_creation_failed;
    }

    inline _App_error _Perform_decryption(program_options& _Options) {
        if (!_Options.path_to_file.native().ends_with(L".efc")) { // must end with .EFC extension
            return _App_error::_Invalid_file;
        }

        const path& _Dest_path = _Remove_internal_extension(_Options.path_to_file);
        if (::mjx::exists(_Dest_path)) { // must not exists
            return _App_error::_File_already_exists;
        }

        // Note: The newly created file is initially set as temporary to handle potential issues.
        //       Upon successful operation, it will be converted to a regular file.
        temporary_file _Dest_file;
        if (!::mjx::create_temporary_file(_Dest_path, _Dest_file)) {
            return _App_error::_File_creation_failed;
        }

        file _Src_file(_Options.path_to_file, file_access::read, file_share::read);
        file_stream _Src_stream(_Src_file);
        file_stream _Dest_stream(_Dest_file);
        if (!_Src_stream.is_open() || !_Dest_stream.is_open()) { // both streams must be valid
            return _App_error::_Invalid_file;
        }

        file_metadata _Meta = load_metadata(_Src_stream);
        if (!_Meta.signature.is_recognized()) { // signature not recognized, break
            return _App_error::_Signature_not_recognized;
        }

        const key& _Key = derive_key(_Options.password.as_view(), _Meta.salt);
        if (!_Key.valid()) {
            return _App_error::_Key_derivation_failed;
        }

        encryption_engine _EEng;
        file_encryption_engine _FEng(_Src_stream, _Dest_stream, _EEng);
        if (!_FEng.decrypt(_Key, _Meta.iv, _Meta.tag)) {
            return _App_error::_Decryption_failed;
        }

        return _Dest_file.make_regular() ? _App_error::_Success : _App_error::_File_creation_failed;
    }

    inline _App_error _Unsafe_entry_point(program_options& _Options) {
        if (_Options.operation == operation::help) { // neither path nor key is required
            _Show_help();
            return _App_error::_Success;
        }

        if (_Options.path_to_file.empty()) {
            return _App_error::_Path_not_specified;
        }

        if (_Options.password.empty()) {
            return _App_error::_Password_not_specified;
        }

        switch (_Options.operation) {
        case operation::encryption:
            return _Perform_encryption(_Options);
        case operation::decryption:
            return _Perform_decryption(_Options);
        default:
            return _App_error::_Operation_not_specified;
        }
    }

    inline int _Entry_point(program_options& _Options) noexcept {
        _App_error _Error;
        try {
            _Error = _Unsafe_entry_point(_Options);
        } catch (...) {
            _Error = _App_error::_Unknown_error;
        }

        if (_Error != _App_error::_Success) { // report an error
            _Report_error(_Error);
        }

        return static_cast<int>(_Error);
    }
} // namespace mjx

int wmain(int _Count, wchar_t** _Args) {
    ::mjx::program_options _Options;
    ::mjx::parse_program_args(_Count, _Args, _Options);
    return ::mjx::_Entry_point(_Options);
}